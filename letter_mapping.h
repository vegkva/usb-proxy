#ifndef LETTER_MAPPING_H
#define LETTER_MAPPING_H

#include <map>
#include <string>
#include <vector>

std::string getAsciiLetter(const std::string& bytePattern);
std::vector<unsigned int> stringToBytePattern(const std::string& input);

#endif
