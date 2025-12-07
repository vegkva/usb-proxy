#include "WebServer.h"
#include "cors.h"
#include "letter_mapping.h"
#include "proxy.h"
#include <crow.h>

WebServer::WebServer(CommandQueue &queue) : commandQueue(queue) {}

WebServer::~WebServer() { stop(); }

void WebServer::start(int port) {
  running = true;
  serverThread = std::thread(&WebServer::run, this, port);
}

void WebServer::stop() {
  if (running) {
    running = false;
    // Crow doesn't have a clean stop() so we detach.
    serverThread.detach();
  }
}

void WebServer::run(int port) {
  crow::App<CORS> app;

  // POST /command { "key": "a" }
  CROW_ROUTE(app, "/command")
      .methods("POST"_method)([this](const crow::request &req) {
        auto body = crow::json::load(req.body);
        if (!body || !body.has("key"))
          return crow::response(400, "Invalid JSON");

        std::string key = body["key"].s();
        printf("key: %s", key.c_str());
        std::string userInput = key; // Extract user input
        int count = 0;
        std::vector<unsigned int> cmdVector = stringToBytePattern(userInput);
        for (auto letter : userInput) {
          printf("%c: ", letter);
          for (auto i : cmdVector) {
            if (count == 8) {
              printf("\n");
              count = 0;
              break;
            }
            printf(" %d", i);

            count++;
          }
        }
        inject(userInput);

        crow::json::wvalue result;
        result["status"] = "ok";
        return crow::response(result);
      });

  app.port(port).multithreaded().run();
}
