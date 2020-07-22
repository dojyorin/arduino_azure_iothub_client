#ifndef IoTHub_Client_Header
#define IoTHub_Client_Header

#include "PubSubClient.h"
#include "Arduino_JSON.h"
#include "Base64.h"
#include "Percent.h"

#include "hmac/hmac.h"

#define MQTT_MAX_PACKET_SIZE 1280
#define MQTT_MAX_TRANSFER_SIZE 1280

typedef void(*CallbackHandler)(const char* data);

class IoTHub{
public:
	IoTHub(PubSubClient client);
	~IoTHub();

	void setCallback(CallbackHandler func);
	void begin(String cs);
	bool connect();
	bool push(JSONVar data);

private:
	PubSubClient mqtt;
	CallbackHandler handler;

	static const uint16_t port = 8883;
	static const uint32_t expiry = 1737504000;
	static void callback(char* topic, byte* payload, unsigned int length);

	char* host;
	char* id;
	char* user;
	char* key;
	char* sas;
	char* getUrl;
	char* postUrl;
}

#endif