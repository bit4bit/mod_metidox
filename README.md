# mod_metidox

Research about writing endpoint for freeswitch.

This module allow receive and generate calls using tox protocol.

Endpoint para freeswitch

# ejemplo Dialplan

~~~
    <extension name="tox-friend">
      <condition field="destination_number" expression="^tox/(.+)$">
        <action application="set" data="hangup_after_bridge=true"/>
        <action application="bridge" data="metidox/$1"/>
      </condition>
    </extension>
~~~

# TODO

-[X] Generate call
-[X] Receive call
-[X] Send audio
-[ ] Receive audio

# CONTRIBUTING

See https://chiselapp.com/user/bit4bit/repository/mod_metidox/index
