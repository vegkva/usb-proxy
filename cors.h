#pragma once
#include "crow.h"

struct CORS {
  struct context {};

  void before_handle(crow::request &req, crow::response &res, context &) {
    // Allow all origins (you can restrict later)
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.add_header("Access-Control-Allow-Headers", "Content-Type");

    // Handle browser preflight OPTIONS request
    if (req.method == crow::HTTPMethod::OPTIONS) {
      res.code = 204; // No Content
      res.end();
    }
  }

  void after_handle(crow::request &, crow::response &res, context &) {
    // Ensure headers are included in all responses
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.add_header("Access-Control-Allow-Headers", "Content-Type");
  }
};
