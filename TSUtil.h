#ifndef TSUTIL_H_
#define TSUTIL_H_

#include "sha256.h"

#include <cstdint>
#include <string>
#include <vector>


class TSUtil {
public:
  static bool isSlowPhase(size_t identity_length, uint64_t counter) {
    return identity_length + TSUtil::decimalLength(counter) + 1 + 8 > 128;
  }

  static uint64_t itsUntilSlowPhase(size_t identity_length, uint64_t counter) {
    if (isSlowPhase(identity_length, counter)) { return 0; }
    uint64_t requiredCounterLength = (128 - 8 - 1 - identity_length) + 1;
    return powlong(10, requiredCounterLength - 1) - counter;
  }

  static uint8_t decimalLength(uint64_t num) {
    if (num == 0) { return 1; }
    uint8_t len = 0;
    while (num != 0) {
      len++;
      num /= 10;
    }
    return len;
  }

  static uint64_t itsConstantCounterLength(uint64_t counter) {
    uint64_t counterlen = decimalLength(counter);
    return counterlen < 20 ? (powlong(10, counterlen) - counter) : UINT64_MAX;
  }

  static uint8_t getDifficulty(const std::string& publickey, uint64_t counter) {
    std::string hashinput;
    hashinput.reserve(publickey.size() + 32);
    hashinput.append(publickey);
    hashinput.append(std::to_string(counter));

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, reinterpret_cast<const uint8_t*>(hashinput.data()), hashinput.size());
    uint8_t hash[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, hash);

    uint8_t zerobytes = 0;
    while (zerobytes < SHA256_BLOCK_SIZE && hash[zerobytes] == 0) {
      zerobytes++;
    }
    uint8_t zerobits = 0;
    if (zerobytes < SHA256_BLOCK_SIZE) {
      uint8_t lastbyte = hash[zerobytes];
      while ((lastbyte & 1) == 0) {
        zerobits++;
        lastbyte >>= 1;
      }
    }

    return static_cast<uint8_t>(8 * zerobytes + zerobits);
  }

private:
  static uint64_t powlong(uint64_t base, uint64_t exp) {
    uint64_t result = 1;
    while (exp != 0) {
      if ((exp & 1) != 0) { result *= base; }
      exp >>= 1;
      base *= base;
    }
    return result;
  }
};

#endif
