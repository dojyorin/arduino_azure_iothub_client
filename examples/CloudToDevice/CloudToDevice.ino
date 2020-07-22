#include "WiFi101.h"
#include "PubSubClient.h"
#include "Arduino_JSON.h"

#include "IoTHub_Client.h"

WiFiSSLClient tls = WiFiSSLClient();
IoTHub azure = IoTHub(PubSubClient(tls));

void setup(){
    // Serial
    Serial.begin(115200);
    while(!Serial);

    // WiFi
    WiFi.setPins(8, 7, 4, 2);
    WiFi.begin("my ssid", "my password");

    Serial.print("SSID: ");
    Serial.println(WiFi.SSID());
    Serial.print("IP Addr: ");
    Serial.println((IPAddress)WiFi.localIP());

    // Azure
    azure.begin("my connection string");

    azure.setCallback([](const char* res){
        Serial.print("Received: ");
        Serial.println(res);

        JSONVar jsonRoot;
        JSONVar data;
        JSONVar info;

        data["hoge"] = "fuga";
        info["foo"] = 123;

        jsonRoot["data"] = data;
        jsonRoot["info"] = info;

        azure.push(jsonRoot);

        Serial.println("Callback to Cloud!");
    });
}

void loop(){
    azure.connect();
    delay(1000);
}