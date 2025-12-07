#pragma once
#include "CommandQueue.h"
#include <atomic>
#include <thread>

class WebServer {
public:
  WebServer(CommandQueue &queue);
  ~WebServer();

  void start(int port = 8080);
  void stop();

private:
  void run(int port);

  CommandQueue &commandQueue;
  std::thread serverThread;
  std::atomic<bool> running{false};
};
