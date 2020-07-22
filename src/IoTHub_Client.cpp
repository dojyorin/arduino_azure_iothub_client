#include "IoTHub_Client.h"

namespace{
	void* self;

	String split(String data, char separator, uint8_t index){
		uint8_t found = 0;
		uint32_t nowIndex[] = {0, -1};
		uint32_t maxIndex = data.length() - 1;

		for(uint32_t i = 0; i <= maxIndex && found <= index; i++){
			if(data.charAt(i) == separator || i == maxIndex){
				found++;
				nowIndex[0] = nowIndex[1] + 1;
				nowIndex[1] = (i == maxIndex) ? i + 1 : i;
			}
		}

		return found > index ? data.substring(nowIndex[0], nowIndex[1]) : "";
	}

	String sas(const char* key, String url, uint32_t expiry){
		uint8_t decKey[BASE64::dLength(key, false)];
		BASE64::decode(key, decKey, strlen(key));

		char* msg;
		String _host = url + "\n" + expiry;
		_host.toCharArray(msg, _host.length() + 1);

		char hmacOutput[65];
		HMAC_SHA256::generate((const char*)decKey, (const char*)msg, hmacOutput);

		char encMsg[BASE64::eLength(32)];
		BASE64::encode((const uint8_t*)hmacOutput, encMsg, 32);

		char encUrl[PERCENT::eLength(encMsg)];
		PERCENT::encode(encMsg, encUrl);

		return "SharedAccessSignature sr=" + url + "&sig=" + encUrl + "&se=" + expiry;
	}
}

IoTHub::IoTHub(PubSubClient client){
	this->mqtt = client;
}

IoTHub::~IoTHub(){}

void IoTHub::callback(char* topic, byte* payload, unsigned int length){
	char* rxData;
	for(uint16_t i = 0; i < length; i++){
		*rxData++ = (char)payload[i];
	}
	*rxData = '\0';

	((IoTHub*)self)->handler((const char*)rxData);
}

void IoTHub::setCallback(CallbackHandler func){
	self = (void*)this;
	this->handler = func;
	this->mqtt.setCallback(IoTHub::callback);
}

void IoTHub::begin(String cs){
	String _host = split(split(cs, ';', 0), '=', 1);
	_host.toCharArray(this->host, _host.length() + 1);

	String _id = split(split(cs, ';', 1), '=', 1);
	_id.toCharArray(this->id, _id.length() + 1);

	String _key = split(split(cs, ';', 2), '=', 1);
	_key.toCharArray(this->key, _key.length() + 1);

	String _user = _host + "/" + _id;
	_user.toCharArray(this->user, _user.length() + 1);

	char encHost[PERCENT::eLength(this->host)];
	PERCENT::encode(this->host, encHost);
	String _sas = sas(this->key, (String)encHost + "%2Fdevices%2F" + _id, this->expiry);
	_sas.toCharArray(this->sas, _sas.length() + 1);

	String _getUrl = "devices/" + _id + "/messages/devicebound/#";
	_getUrl.toCharArray(this->getUrl, _getUrl.length() + 1);

	String _postUrl = "devices/" + _id + "/messages/events/";
	_postUrl.toCharArray(this->postUrl, _postUrl.length() + 1);

	this->mqtt.setServer(this->host, this->port);
}

bool IoTHub::connect(){
	while(!this->mqtt.connected()){
		Serial.print("MQTTS Connection: ");

		if(this->mqtt.connect(this->id, this->user, this->sas)){
			Serial.println("Success");
			this->mqtt.subscribe(this->getUrl);
		}
		else{
			Serial.println("Failed");
			Serial.print("Code: ");
			Serial.print(this->mqtt.state());
			Serial.println(" - Retry after 5 seconds");
			delay(5000);
		}
	}
	return this->mqtt.loop();
}

bool IoTHub::push(JSONVar json){
	char* txData;
	String _json = JSON.stringify(json);
	_json.toCharArray(txData, _json.length() + 1);

	return this->mqtt.publish(this->postUrl, (const char*)txData);
}