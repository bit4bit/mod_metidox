/*
 * Copyright (C) 2021 Jovany Leandro G.C <bit4bit@riseup.net>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * derivated work from mod_reference.c
 */
#include <switch.h>

#include <tox/tox.h>
#include <tox/toxav.h>
#include <sodium/utils.h>

#include "helpers.h"


#define FRAME_QUEUE_LEN 960
#define MIN(a, b) (a < b ? a : b)

#define LOGA(KIND, ...)  switch_log_printf(SWITCH_CHANNEL_LOG, KIND, __VA_ARGS__ );
#define SAMPLERATE_METIDOX 8000

SWITCH_MODULE_LOAD_FUNCTION(mod_metidox_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_metidox_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_metidox_runtime);
SWITCH_MODULE_DEFINITION(mod_metidox, mod_metidox_load, mod_metidox_shutdown, mod_metidox_runtime);	//mod_metidox_runtime);


switch_endpoint_interface_t *metidox_endpoint_interface;
static switch_memory_pool_t *module_pool = NULL;


typedef enum {
	TFLAG_IO = (1 << 0),
	TFLAG_INBOUND = (1 << 1),
	TFLAG_OUTBOUND = (1 << 2),
	TFLAG_DTMF = (1 << 3),
	TFLAG_VOICE = (1 << 4),
	TFLAG_HANGUP = (1 << 5),
	TFLAG_LINEAR = (1 << 6),
	TFLAG_CODEC = (1 << 7),
	TFLAG_BREAK = (1 << 8)
} TFLAGS;

typedef enum {
	GFLAG_MY_CODEC_PREFS = (1 << 0)
} GFLAGS;


static struct {
	int done;
	char *tox_profile;
	char *tox_name;
	char *tox_status_message;
	
	int debug;
	char *ip;
	int port;
	char *context;
	char *dialplan;
	char *destination;
	char *codec_string;
	char *codec_order[SWITCH_MAX_CODECS];
	int codec_order_last;
	char *codec_rates_string;
	char *codec_rates[SWITCH_MAX_CODECS];
	int codec_rates_last;
	unsigned int flags;
	int calls;
	switch_mutex_t *mutex;
} globals;

typedef struct {
	uint32_t friend_number;
	int16_t *pcm;
	size_t sample_count;
	uint8_t channels;
	uint32_t sampling_rate;
	uint32_t timestamp;
} tox_frame_t;

static struct {
	char *session_uuid[10];
	switch_core_session_t *session[10];
	switch_memory_pool_t *pool;
	switch_mutex_t *mutex;
} toxcalls;

struct private_object {
	uint32_t friend_number;
	ToxAV *toxav;
	unsigned int flags;
	switch_codec_t read_codec;
	switch_codec_t write_codec;
	switch_frame_t read_frame;
	switch_frame_t *tmp_read_frame;
	unsigned char databuf[SWITCH_RECOMMENDED_BUFFER_SIZE];
	switch_core_session_t *session;
	switch_caller_profile_t *caller_profile;
	switch_memory_pool_t *pool;
	switch_timer_t timer_read;
	switch_mutex_t *mutex;
	switch_mutex_t *flag_mutex;

	switch_queue_t *frame_queue;
};

typedef struct private_object private_t;
struct Tox_Options tox_options;
static Tox *tox = NULL;
static ToxAV *toxav = NULL;
switch_thread_t *toxav_thread = NULL;

SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_tox_profile, globals.tox_profile);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_tox_name, globals.tox_name);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_tox_status_message, globals.tox_status_message);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_context, globals.context);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_dialplan, globals.dialplan);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_destination, globals.destination);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_codec_string, globals.codec_string);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_codec_rates_string, globals.codec_rates_string);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_ip, globals.ip);



static switch_status_t channel_on_init(switch_core_session_t *session);
static switch_status_t channel_on_hangup(switch_core_session_t *session);
static switch_status_t channel_on_destroy(switch_core_session_t *session);
static switch_status_t channel_on_routing(switch_core_session_t *session);
static switch_status_t channel_on_exchange_media(switch_core_session_t *session);
static switch_status_t channel_on_soft_execute(switch_core_session_t *session);
static switch_call_cause_t channel_outgoing_channel(switch_core_session_t *session, switch_event_t *var_event,
													switch_caller_profile_t *outbound_profile,
													switch_core_session_t **new_session, switch_memory_pool_t **pool, switch_originate_flag_t flags,
													switch_call_cause_t *cancel_cause);
static switch_status_t channel_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags, int stream_id);
static switch_status_t channel_write_frame(switch_core_session_t *session, switch_frame_t *frame, switch_io_flag_t flags, int stream_id);
static switch_status_t channel_kill_channel(switch_core_session_t *session, int sig);


static switch_status_t metidox_codec(private_t *tech_pvt, int sample_rate, int codec_ms)
{
	switch_core_session_t *session = NULL;

	if (switch_core_codec_init
		//@TODO force 48000 tox sampling_rate
		(&tech_pvt->read_codec, "L16", NULL, NULL, 48000, codec_ms, 1,
		 SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL, NULL) != SWITCH_STATUS_SUCCESS) {
		LOGA(SWITCH_LOG_ERROR, "Can't load codec?\n");
		return SWITCH_STATUS_FALSE;
	}
	tech_pvt->read_frame.rate = 48000;
	tech_pvt->read_frame.codec = &tech_pvt->read_codec;

	if (switch_core_codec_init
		(&tech_pvt->write_codec, "L16", NULL, NULL, sample_rate, codec_ms, 1,
		 SWITCH_CODEC_FLAG_ENCODE | SWITCH_CODEC_FLAG_DECODE, NULL, NULL) != SWITCH_STATUS_SUCCESS) {
		LOGA(SWITCH_LOG_ERROR, "Can't load code?\n");
		switch_core_codec_destroy(&tech_pvt->read_codec);
		return SWITCH_STATUS_FALSE;
	}
   
	//algunos modulos lo consulta por uuid
	//y tienen la razon ya que switch_core_session_locate
	//es bloqueante
	session = tech_pvt->session;
	switch_assert(session != NULL);
	switch_core_session_set_read_codec(session, &tech_pvt->read_codec);
	switch_core_session_set_write_codec(session, &tech_pvt->write_codec);
	switch_core_session_rwunlock(session);
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t tech_init(private_t *tech_pvt, switch_core_session_t *session)
{
	tech_pvt->read_frame.data = tech_pvt->databuf;
	tech_pvt->read_frame.buflen = sizeof(tech_pvt->databuf);
	switch_mutex_init(&tech_pvt->mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));
	switch_mutex_init(&tech_pvt->flag_mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));
	switch_queue_create(&tech_pvt->frame_queue, FRAME_QUEUE_LEN, switch_core_session_get_pool(session));
	switch_core_session_set_private(session, tech_pvt);
	tech_pvt->session = session;
	tech_pvt->toxav = toxav;
	if (switch_core_new_memory_pool(&tech_pvt->pool) != SWITCH_STATUS_SUCCESS ){
		LOGA(SWITCH_LOG_ERROR, "metidox_codec failde switch_core_new_memory_pool\n");
		return SWITCH_STATUS_FALSE;
	}
	
	if (metidox_codec(tech_pvt, SAMPLERATE_METIDOX, 20) != SWITCH_STATUS_SUCCESS) {
		LOGA(SWITCH_LOG_ERROR, "metidox_codec failed\n");
		return SWITCH_STATUS_FALSE;
	}

	if (switch_core_timer_init(&tech_pvt->timer_read, "soft", 20, tech_pvt->read_codec.implementation->samples_per_packet, module_pool) != SWITCH_STATUS_SUCCESS) {
		LOGA(SWITCH_LOG_ERROR, "tech_init timer error read\n");
		return SWITCH_STATUS_FALSE;
	}
	switch_core_timer_sync(&tech_pvt->timer_read);
	switch_clear_flag_locked(tech_pvt, TFLAG_HANGUP);
	return SWITCH_STATUS_SUCCESS;
}


/*
   State methods they get called when the state changes to the specific state
   returning SWITCH_STATUS_SUCCESS tells the core to execute the standard state method next
   so if you fully implement the state you can return SWITCH_STATUS_FALSE to skip it.
*/
static switch_status_t channel_on_init(switch_core_session_t *session)
{
	switch_channel_t *channel;
	private_t *tech_pvt = NULL;


	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "channel_on_init\n");
	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);
	switch_set_flag_locked(tech_pvt, TFLAG_IO);

	switch_mutex_lock(globals.mutex);
	globals.calls++;
	switch_mutex_unlock(globals.mutex);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_routing(switch_core_session_t *session)
{
	switch_channel_t *channel = NULL;
	private_t *tech_pvt = NULL;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "channel_on_routing\n");
	
	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s CHANNEL ROUTING\n", switch_channel_get_name(channel));

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_execute(switch_core_session_t *session)
{

	switch_channel_t *channel = NULL;
	private_t *tech_pvt = NULL;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "channel_on_execute\n");
	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s CHANNEL EXECUTE\n", switch_channel_get_name(channel));


	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_destroy(switch_core_session_t *session)
{
	switch_channel_t *channel = NULL;
	private_t *tech_pvt = NULL;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "channel_on_destroy\n");
	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);

	if (tech_pvt) {
		if (switch_core_codec_ready(&tech_pvt->read_codec)) {
			switch_core_codec_destroy(&tech_pvt->read_codec);
		}

		if (switch_core_codec_ready(&tech_pvt->write_codec)) {
			switch_core_codec_destroy(&tech_pvt->write_codec);
		}

		switch_core_destroy_memory_pool(&tech_pvt->pool);
	}

	return SWITCH_STATUS_SUCCESS;
}


static switch_status_t channel_on_hangup(switch_core_session_t *session)
{
	switch_channel_t *channel = NULL;
	private_t *tech_pvt = NULL;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "channel_on_hangup\n");
	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	switch_clear_flag_locked(tech_pvt, TFLAG_IO);
	switch_clear_flag_locked(tech_pvt, TFLAG_VOICE);
	switch_set_flag_locked(tech_pvt, TFLAG_HANGUP);
	//switch_thread_cond_signal(tech_pvt->cond);

	toxav_call_control(tech_pvt->toxav, tech_pvt->friend_number,
					   TOXAV_CALL_CONTROL_CANCEL, NULL);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s CHANNEL HANGUP\n", switch_channel_get_name(channel));
	switch_mutex_lock(globals.mutex);
	globals.calls--;
	if (globals.calls < 0) {
		globals.calls = 0;
	}
	switch_mutex_unlock(globals.mutex);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_kill_channel(switch_core_session_t *session, int sig)
{
	switch_channel_t *channel = NULL;
	private_t *tech_pvt = NULL;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "channel_kill_channel sig %d\n", sig);
	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	switch (sig) {
	case SWITCH_SIG_KILL:
		switch_clear_flag_locked(tech_pvt, TFLAG_IO);
		switch_clear_flag_locked(tech_pvt, TFLAG_VOICE);
		switch_set_flag(tech_pvt, TFLAG_HANGUP);

		break;
	default:
		break;
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_exchange_media(switch_core_session_t *session)
{
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "CHANNEL EXCHANGE MEDIA\n");
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_on_soft_execute(switch_core_session_t *session)
{
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "CHANNEL TRANSMIT\n");
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_send_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf)
{
	private_t *tech_pvt = switch_core_session_get_private(session);
	switch_assert(tech_pvt != NULL);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t channel_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags, int stream_id)
{
	switch_channel_t *channel = NULL;
	private_t *tech_pvt = NULL;
	switch_byte_t *data;
	
	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	if (!switch_channel_ready(channel) || !switch_test_flag(tech_pvt, TFLAG_IO)) {
		LOGA(SWITCH_LOG_ERROR, "channel not ready\n");
		return SWITCH_STATUS_FALSE;
	}

	if (switch_test_flag(tech_pvt, TFLAG_HANGUP)) {
		LOGA(SWITCH_LOG_INFO, "tflag hangup\n");
		return SWITCH_STATUS_FALSE;
	}

	tech_pvt->read_frame.datalen = 0;
	tech_pvt->read_frame.flags = SFF_NONE;
	*frame = NULL;

	while (switch_test_flag(tech_pvt, TFLAG_IO)) {
		tech_pvt->read_frame.datalen = 0;
		tech_pvt->read_frame.flags = SFF_NONE;

		if (switch_test_flag(tech_pvt, TFLAG_HANGUP)) {
			LOGA(SWITCH_LOG_INFO, "tflag hangup\n");
			return SWITCH_STATUS_FALSE;
		}
			
		if (switch_test_flag(tech_pvt, TFLAG_BREAK)) {
			switch_clear_flag(tech_pvt, TFLAG_BREAK);
			LOGA(SWITCH_LOG_INFO, "break channel\n");
			goto cng;
		}

		if (!switch_test_flag(tech_pvt, TFLAG_IO)) {
			LOGA(SWITCH_LOG_INFO, "TFLAG_IO OFF\n");
			return SWITCH_STATUS_FALSE;
		}

		{
			void *pop;
			if (switch_queue_trypop(tech_pvt->frame_queue, &pop) == SWITCH_STATUS_SUCCESS && pop) {
				switch_clear_flag_locked(tech_pvt, TFLAG_VOICE);
				if (tech_pvt->tmp_read_frame) {
					switch_frame_free(&tech_pvt->tmp_read_frame);
				}
				tech_pvt->tmp_read_frame = (switch_frame_t *) pop;
				tech_pvt->tmp_read_frame->codec = &tech_pvt->read_codec;
				*frame = tech_pvt->tmp_read_frame;	
			} else {
				continue;
			}
		}

#if SWITCH_BYTE_ORDER == __BIG_ENDIAN
		if (switch_test_flag(tech_pvt, TFLAG_LINEAR)) {
			switch_swap_linear((*frame)->data, (int) (*frame)->datalen / 2);
		}
#endif
		LOGA(SWITCH_LOG_INFO, "channel read TFLAG_VOICE\n");
		return SWITCH_STATUS_SUCCESS;
	}

  cng:
	data = (switch_byte_t *) tech_pvt->read_frame.data;
	data[0] = 65;
	data[1] = 0;
	tech_pvt->read_frame.datalen = 2;
	tech_pvt->read_frame.flags = SFF_CNG;
	*frame = &tech_pvt->read_frame;
	return SWITCH_STATUS_SUCCESS;

}

static switch_status_t channel_write_frame(switch_core_session_t *session, switch_frame_t *frame, switch_io_flag_t flags, int stream_id)
{
	switch_channel_t *channel = NULL;
	private_t *tech_pvt = NULL;


	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);


	if (!switch_channel_ready(channel) || !switch_test_flag(tech_pvt, TFLAG_IO)) {
		LOGA(SWITCH_LOG_ERROR, "channel not ready \n");
		return SWITCH_STATUS_FALSE;
	}

#if SWITCH_BYTE_ORDER == __BIG_ENDIAN
	if (switch_test_flag(tech_pvt, TFLAG_LINEAR)) {
		switch_swap_linear(frame->data, (int) frame->datalen / 2);
	}
#endif

	{
		//LOGA(SWITCH_LOG_INFO, "send frame samples %u  channels %u\n", frame->samples, frame->channels);
		TOXAV_ERR_SEND_FRAME errframe;
		toxav_audio_send_frame(toxav, tech_pvt->friend_number,
							   (int16_t *) frame->data,
							   frame->samples,
							   frame->channels,
							   SAMPLERATE_METIDOX,
							   &errframe);
		if (errframe == TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND
			//|| errframe == TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL
			) {
			LOGA(SWITCH_LOG_ERROR, "toxav_audio_send_frame: failed %d\n", errframe);
			return SWITCH_STATUS_GENERR;
		}
	}

	return SWITCH_STATUS_SUCCESS;

}

static switch_status_t channel_answer_channel(switch_core_session_t *session)
{
	private_t *tech_pvt;
	switch_channel_t *channel = NULL;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "channel_answer_channel\n");
	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	return SWITCH_STATUS_SUCCESS;
}


static switch_status_t channel_receive_message(switch_core_session_t *session, switch_core_session_message_t *msg)
{
	switch_channel_t *channel;
	private_t *tech_pvt;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "channel_receive_message: message_id %d\n", msg->message_id);
	channel = switch_core_session_get_channel(session);
	assert(channel != NULL);

	tech_pvt = (private_t *) switch_core_session_get_private(session);
	assert(tech_pvt != NULL);

	switch (msg->message_id) {
	case SWITCH_MESSAGE_INDICATE_ANSWER:
		channel_answer_channel(session);
		break;
	case SWITCH_MESSAGE_INDICATE_PROGRESS:
		channel_answer_channel(session);
		break;
	case SWITCH_MESSAGE_INDICATE_AUDIO_SYNC:
		switch_core_timer_sync(&tech_pvt->timer_read);
		break;
	default:
		break;
	}

	return SWITCH_STATUS_SUCCESS;
}

/* Make sure when you have 2 sessions in the same scope that you pass the appropriate one to the routines
   that allocate memory or you will have 1 channel with memory allocated from another channel's pool!
*/
static switch_call_cause_t channel_outgoing_channel(switch_core_session_t *session, switch_event_t *var_event,
													switch_caller_profile_t *outbound_profile,
													switch_core_session_t **new_session, switch_memory_pool_t **pool, switch_originate_flag_t flags,
													switch_call_cause_t *cancel_cause)
{
	char session_uuid[SWITCH_UUID_FORMATTED_LENGTH+1];
	//TODO se requiere uuid para la session
	switch_uuid_str((char *)&session_uuid, sizeof(session_uuid));
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "channel_outgoing_channel\n");
	if ((*new_session = switch_core_session_request(metidox_endpoint_interface, SWITCH_CALL_DIRECTION_OUTBOUND, flags, pool)) != 0) {
		private_t *tech_pvt;
		switch_channel_t *channel;
		switch_caller_profile_t *caller_profile;

		switch_core_session_add_stream(*new_session, NULL);
		if ((tech_pvt = (private_t *) switch_core_session_alloc(*new_session, sizeof(private_t))) != 0) {
			channel = switch_core_session_get_channel(*new_session);
			tech_init(tech_pvt, *new_session);
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(*new_session), SWITCH_LOG_CRIT, "Hey where is my memory pool?\n");
			switch_core_session_destroy(new_session);
			return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
		}

		if (outbound_profile) {
			char name[128];
			uint32_t friend_number;
			int toxerr;
			uint8_t friend_public_key[TOX_PUBLIC_KEY_SIZE];

			hex2bin(friend_public_key, TOX_PUBLIC_KEY_SIZE,
					outbound_profile->destination_number, strlen(outbound_profile->destination_number));
			snprintf(name, sizeof(name), "METIDOX/%s", outbound_profile->destination_number);
			switch_channel_set_name(channel, name);

			caller_profile = switch_caller_profile_clone(*new_session, outbound_profile);
			switch_channel_set_caller_profile(channel, caller_profile);
			tech_pvt->caller_profile = caller_profile;

			friend_number = tox_friend_by_public_key(tox,
													 friend_public_key,
													 (TOX_ERR_FRIEND_BY_PUBLIC_KEY*)&toxerr);
			if (toxerr != TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "failed to get friend_number: %d\n", toxerr);
				return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
			}
			toxav_call(toxav, friend_number, 64, 0, (TOXAV_ERR_CALL*)&toxerr);

			if (toxerr != TOXAV_ERR_CALL_OK) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "toxav_call error %d\n", toxerr);
				return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
			}
			tech_pvt->friend_number = friend_number;
			switch_mutex_lock(toxcalls.mutex);
			toxcalls.session[friend_number] = *new_session;
			//toxcalls.session_uuid[friend_number] = switch_core_session_strdup(session, (char *)&session_uuid);
			switch_mutex_unlock(toxcalls.mutex);
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(*new_session), SWITCH_LOG_ERROR, "Doh! no caller profile\n");
			switch_core_session_destroy(new_session);
			return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;
		}


		switch_set_flag_locked(tech_pvt, TFLAG_OUTBOUND);
		switch_channel_set_state(channel, CS_INIT);
		switch_channel_mark_ring_ready(channel);
		return SWITCH_CAUSE_SUCCESS;
	}

	return SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER;

}

static switch_status_t channel_receive_event(switch_core_session_t *session, switch_event_t *event)
{
	struct private_object *tech_pvt = switch_core_session_get_private(session);
	char *body = switch_event_get_body(event);
	switch_assert(tech_pvt != NULL);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "channel_receive_event\n");
	if (!body) {
		body = "";
	}

	return SWITCH_STATUS_SUCCESS;
}



switch_state_handler_table_t metidox_state_handlers = {
	/*.on_init */ channel_on_init,
	/*.on_routing */ channel_on_routing,
	/*.on_execute */ channel_on_execute,
	/*.on_hangup */ channel_on_hangup,
	/*.on_exchange_media */ channel_on_exchange_media,
	/*.on_soft_execute */ channel_on_soft_execute,
	/*.on_consume_media */ NULL,
	/*.on_hibernate */ NULL,
	/*.on_reset */ NULL,
	/*.on_park */ NULL,
	/*.on_reporting */ NULL,
	/*.on_destroy */ channel_on_destroy
};

switch_io_routines_t metidox_io_routines = {
	/*.outgoing_channel */ channel_outgoing_channel,
	/*.read_frame */ channel_read_frame,
	//FS escribe a canal/TOX
	/*.write_frame */ channel_write_frame,
	/*.kill_channel */ channel_kill_channel,
	/*.send_dtmf */ channel_send_dtmf,
	/*.receive_message */ channel_receive_message,
	/*.receive_event */ channel_receive_event
};

static switch_status_t load_config(void)
{
	char *cf = "tox.conf";
	switch_xml_t cfg, xml, settings, param;

	memset(&globals, 0, sizeof(globals));
	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, module_pool);
	switch_mutex_init(&toxcalls.mutex, SWITCH_MUTEX_NESTED, module_pool);
	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	set_global_context("default");
	set_global_dialplan("XML");
	set_global_destination("metidox");
	
	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");

			if (strcmp(var, "tox-profile")) {
				set_global_tox_profile(val);
			} else if (!strcmp(var, "tox-name")) {
				set_global_tox_name(val);
			} else if (!strcmp(var, "tox-status-message")) {
				set_global_tox_status_message(val);
			} else if (!strcmp(var, "debug")) {
				globals.debug = atoi(val);
			} else if (!strcmp(var, "port")) {
				globals.port = atoi(val);
			} else if (!strcmp(var, "ip")) {
				set_global_ip(val);
			} else if (!strcmp(var, "codec-master")) {
				if (!strcasecmp(val, "us")) {
					switch_set_flag(&globals, GFLAG_MY_CODEC_PREFS);
				}
			} else if (!strcmp(var, "destination")) {
				set_global_destination(val);
			} else if (!strcmp(var, "context")) {
				set_global_context(val);
			} else if (!strcmp(var, "dialplan")) {
				set_global_dialplan(val);
			} else if (!strcmp(var, "codec-prefs")) {
				set_global_codec_string(val);
				globals.codec_order_last = switch_separate_string(globals.codec_string, ',', globals.codec_order, SWITCH_MAX_CODECS);
			} else if (!strcmp(var, "codec-rates")) {
				set_global_codec_rates_string(val);
				globals.codec_rates_last = switch_separate_string(globals.codec_rates_string, ',', globals.codec_rates, SWITCH_MAX_CODECS);
			}
		}
	}


	if (!globals.tox_profile) {
		set_global_tox_profile("/etc/fs.tox");
	}
	
	if (!globals.tox_name) {
		set_global_tox_name("FS - Metidox");
	}
	
	if (!globals.tox_status_message) {
		set_global_tox_status_message("freeswitch pues!");
	}
	
	if (!globals.dialplan) {
		set_global_dialplan("default");
	}

	if (!globals.port) {
		globals.port = 4569;
	}

	switch_xml_free(xml);

	return SWITCH_STATUS_SUCCESS;
}

void metidox_friend_status_cb(Tox *tox, uint32_t friend_number, TOX_USER_STATUS status, void *user_data) {
	char tox_id_hex[TOX_ADDRESS_SIZE*2 + 1];
	uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
	
	if (tox_friend_get_public_key(tox, friend_number, public_key, NULL)) {
		sodium_bin2hex(tox_id_hex, sizeof(tox_id_hex), public_key, TOX_PUBLIC_KEY_SIZE);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "TOXID FRIEND: %s STATUS %d\n", tox_id_hex, status);
	}
}

void metidox_friend_request_cb(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,   void *user_data)
{
	TOX_ERR_FRIEND_ADD err;
	tox_friend_add_norequest(tox, public_key, &err);
	
	if (err != TOX_ERR_FRIEND_ADD_OK) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "metidox_friend_request_cb: failed %d \n", err);
	} else {

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "NEW FRIEND ADDED\n");
	}
	save_data(tox, globals.tox_profile);
}

void metidox_audio_receive_frame_cb(ToxAV *av, uint32_t friend_number, const int16_t *pcm, size_t sample_count,
									uint8_t channels, uint32_t sampling_rate, void *user_data) {
	switch_core_session_t *session = NULL;
	private_t *tech_pvt = NULL;
	//size_t length = sample_count * channels;

	switch_mutex_lock(toxcalls.mutex);
	session = toxcalls.session[friend_number];
	switch_mutex_unlock(toxcalls.mutex);
	assert(session != NULL);

	tech_pvt = switch_core_session_get_private(session);
	assert(tech_pvt != NULL);
	
	LOGA(SWITCH_LOG_INFO, "metidox_audio_receive_frame_cb for sampling_rate %d channels %d sample_count %d\n", (int)sampling_rate, (int)channels, (int)sample_count);
	//LOGA(SWITCH_LOG_INFO, "metidox_audio_receive_frame_cb for friend %d\n", friend_number);
	//LOGA(SWITCH_LOG_INFO, "metidox_audio_receive_frame_cb for sample_count %d channels %d\n", (int)sample_count, channels);

	int length = sample_count * 2 * channels;

	tech_pvt->read_frame.datalen = length;
	tech_pvt->read_frame.channels = channels;
	tech_pvt->read_frame.samples = sample_count;
	tech_pvt->read_frame.rate = sampling_rate;
	tech_pvt->read_frame.timestamp = tech_pvt->timer_read.samplecount;
	//LOGA(SWITCH_LOG_INFO, "Frame send to FS length %u\n", length);
	memcpy(tech_pvt->read_frame.data, pcm, sizeof(int16_t) * length);
	{
		switch_frame_t *clone;
		if (switch_frame_dup(&tech_pvt->read_frame, &clone) != SWITCH_STATUS_SUCCESS) {
			abort();
		}
		
		if (switch_queue_trypush(tech_pvt->frame_queue, clone) == SWITCH_STATUS_SUCCESS) {
			switch_set_flag_locked(tech_pvt, TFLAG_VOICE);
		}
	}
}


int new_inbound_channel(uint32_t friend_number)
{
	switch_core_session_t *session = NULL;
	switch_channel_t *channel = NULL;
	private_t * tech_pvt = NULL;
	switch_mutex_lock(toxcalls.mutex);
	
	if ((toxcalls.session[friend_number] = switch_core_session_request(metidox_endpoint_interface, SWITCH_CALL_DIRECTION_INBOUND, SOF_NONE, NULL)) != 0) {
		session = toxcalls.session[friend_number];
		
		if ((tech_pvt = (private_t *) switch_core_session_alloc(session, sizeof(private_t))) == NULL) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Hey where is my memory pool?\n");
			switch_core_session_destroy(&session);
			return SWITCH_STATUS_FALSE;
		}

		switch_core_session_add_stream(session, NULL);
		channel = switch_core_session_get_channel(session);
		if (!channel) {
			LOGA(SWITCH_LOG_ERROR, "nOOOO CHANNEL\n");
			switch_core_session_destroy(&session);
			return SWITCH_STATUS_FALSE;
		}
		if (tech_init(tech_pvt, session) != SWITCH_STATUS_SUCCESS) {
			LOGA(SWITCH_LOG_ERROR, "NOO tech_init\n");
			switch_core_session_destroy(&session);
			return SWITCH_STATUS_FALSE;
		}

		if ((tech_pvt->caller_profile =
			 switch_caller_profile_new(switch_core_session_get_pool(session),
									   "metidox",
									   globals.dialplan,
									   "metidox", "metidox",
									   NULL, NULL, NULL, NULL, "mod_metidox",
									   globals.context, globals.destination)) != NULL) {
			char name[128];
			switch_snprintf(name, sizeof(name), "metidox/%d", friend_number);
			switch_channel_set_name(channel, name);
			switch_channel_set_caller_profile(channel, tech_pvt->caller_profile);
		} else {
			return SWITCH_STATUS_FALSE;
		}
		
		switch_channel_set_state(channel, CS_INIT);
		if (switch_core_session_thread_launch(session) != SWITCH_STATUS_SUCCESS) {
			LOGA(SWITCH_LOG_ERROR, "Error spawing thread\n");
			switch_core_session_destroy(&session);
			return SWITCH_STATUS_SUCCESS;
		}
	}
	return SWITCH_STATUS_SUCCESS;
}

void metidox_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data) {
	// answer inbound tox call or cancel
	if (toxav_answer(av, friend_number, 64, 0, NULL))
		new_inbound_channel(friend_number);
	else
		toxav_call_control(av, friend_number, TOXAV_CALL_CONTROL_CANCEL, NULL);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "metidox_call_cb for friend %d\n", friend_number);
}


// apply changes of state calls
void metidox_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
	switch_channel_t *channel = NULL;
	switch_core_session_t *session = NULL;
	private_t *tech_pvt = NULL;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "toxav_call_state_cb state %d for friend %d \n", state, friend_number);

	switch_mutex_lock(toxcalls.mutex);
	session = toxcalls.session[friend_number];
	switch_mutex_unlock(toxcalls.mutex);
	
	switch_assert(session != NULL);

	channel = switch_core_session_get_channel(session);
	switch_assert(channel != NULL);

	tech_pvt = switch_core_session_get_private(session);
	switch_assert(tech_pvt != NULL);

	if (state & TOXAV_FRIEND_CALL_STATE_FINISHED) {
		LOGA(SWITCH_LOG_INFO, "TOX CALL FRIEND FINISHED\n");
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_CLEARING);
	} else if (state & TOXAV_FRIEND_CALL_STATE_ERROR) {
		switch_channel_hangup(channel, SWITCH_CAUSE_NORMAL_TEMPORARY_FAILURE);
	} else if (state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_A) {
		LOGA(SWITCH_LOG_INFO, "TOX CALL FRIEND ANSWERED");
		switch_channel_mark_answered(channel);
	} else if (state && TOXAV_FRIEND_CALL_STATE_SENDING_A) {
		LOGA(SWITCH_LOG_INFO, "TOX FRIEND IS CALLING");
		toxav_call_control(av, friend_number, TOXAV_CALL_CONTROL_RESUME, NULL);
	}
}

// print current tox id
SWITCH_STANDARD_API(my_toxid)
{
	uint8_t tox_id_bin[TOX_ADDRESS_SIZE];
	char tox_id_hex[TOX_ADDRESS_SIZE*2 + 1];

	tox_self_get_address(tox, tox_id_bin);
	sodium_bin2hex(tox_id_hex, sizeof(tox_id_hex), tox_id_bin, sizeof(tox_id_bin));
	
	for (size_t i = 0; i < sizeof(tox_id_hex)-1; i ++) {
		tox_id_hex[i] = toupper(tox_id_hex[i]);
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "TOXID:%s!\n", tox_id_hex);
	return SWITCH_STATUS_SUCCESS;
}

void *SWITCH_THREAD_FUNC metidox_toxav_thread(switch_thread_t *thread, void *obj)
{
	while (!globals.done)  {
		toxav_iterate(toxav);
		switch_yield(toxav_iteration_interval(toxav));
	}
	return NULL;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_metidox_load)
{
	TOXAV_ERR_NEW av_error;
	switch_api_interface_t *api_interface;

	// alloc memory
	module_pool = pool;
	memset(&globals, 0, sizeof(globals));
	memset(&toxcalls, 0, sizeof(toxcalls));

	// initialize globals from xml
	load_config();

	// instantiate module interface
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	metidox_endpoint_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_ENDPOINT_INTERFACE);
	metidox_endpoint_interface->interface_name = "metidox";
	metidox_endpoint_interface->io_routines = &metidox_io_routines;
	metidox_endpoint_interface->state_handler = &metidox_state_handlers;

	// add custom apis
	SWITCH_ADD_API(api_interface, "toxid", "Tox ID", my_toxid, "toxid");

	// initialize tox
	tox_options_default(&tox_options);
	tox = load_tox(&tox_options, globals.tox_profile);
	toxav = toxav_new(tox, &av_error);
	if (av_error != TOXAV_ERR_NEW_OK) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "toxav_new failed: %d\n", av_error);
		return SWITCH_STATUS_FALSE;
	}

	// set tox callbacks
	toxav_callback_call_state(toxav, &metidox_call_state_cb, NULL);
	toxav_callback_call(toxav, &metidox_call_cb, NULL);
	toxav_callback_audio_receive_frame(toxav, &metidox_audio_receive_frame_cb, NULL);
	
	tox_callback_friend_request(tox, metidox_friend_request_cb);
	tox_callback_friend_status(tox, metidox_friend_status_cb);

	// start connection to tox
	tox_self_set_name(tox, (uint8_t *)globals.tox_name, strlen(globals.tox_name), NULL);
	tox_self_set_status_message(tox, (uint8_t*)globals.tox_status_message, strlen(globals.tox_status_message), NULL);
	bootstrap_DHT(tox);
	{
		uint8_t tox_id_bin[TOX_ADDRESS_SIZE];
		char tox_id_hex[TOX_ADDRESS_SIZE*2 + 1];

		tox_self_get_address(tox, tox_id_bin);
		sodium_bin2hex(tox_id_hex, sizeof(tox_id_hex), tox_id_bin, sizeof(tox_id_bin));
		
		for (size_t i = 0; i < sizeof(tox_id_hex)-1; i ++) {
			tox_id_hex[i] = toupper(tox_id_hex[i]);
		}
  		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "TOXID:%s!\n", tox_id_hex);
	}



	// start thread for handling tox
	{
		switch_threadattr_t *toxav_thread_attr = NULL;
		switch_threadattr_create(&toxav_thread_attr, module_pool);
		switch_threadattr_stacksize_set(toxav_thread_attr, SWITCH_THREAD_STACKSIZE);
		switch_thread_create(&toxav_thread, toxav_thread_attr, metidox_toxav_thread,
							 NULL, module_pool);
	}


	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}


SWITCH_MODULE_RUNTIME_FUNCTION(mod_metidox_runtime)
{
	while (!globals.done) {
		tox_iterate(tox, NULL);
		switch_yield(tox_iteration_interval(tox));
	}

	return SWITCH_STATUS_TERM;
}


SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_metidox_shutdown)
{
	int x = 10;
	
	globals.done = 1;
	while (x) {
		x--;
		switch_yield(5000);
	}

	{
		switch_status_t status;
		if (toxav_thread)
			switch_thread_join(&status, toxav_thread);
	}

	x = 10;
	while (x) {
		x--;
		switch_yield(5000);
	}
	
	/* Free dynamically allocated strings */
	switch_safe_free(globals.context);
	switch_safe_free(globals.destination);
	switch_safe_free(globals.dialplan);
	switch_safe_free(globals.codec_string);
	switch_safe_free(globals.codec_rates_string);
	switch_safe_free(globals.ip);

	//segmentation fault
	/*if (tox)
	  tox_kill(tox);*/
	/*if (toxav)
	toxav_kill(toxav);*/
	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
