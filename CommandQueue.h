#pragma once
#include <mutex>
#include <queue>
#include <string>

class CommandQueue {
public:
  void push(const std::string &cmd) {
    std::lock_guard<std::mutex> lock(mtx);
    queue.push(cmd);
  }

  bool pop(std::string &out) {
    std::lock_guard<std::mutex> lock(mtx);
    if (queue.empty())
      return false;
    out = queue.front();
    queue.pop();
    return true;
  }

private:
  std::mutex mtx;
  std::queue<std::string> queue;
};
