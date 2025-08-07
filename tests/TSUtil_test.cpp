#include "../TSUtil.h"
#include <cassert>
#include <string>

int main() {
  // SHA-256("abc0") has one trailing zero bit, producing difficulty 1
  assert(TSUtil::getDifficulty("abc", 0) == 1);
  return 0;
}
