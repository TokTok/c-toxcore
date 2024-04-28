typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

typedef struct {
  uint8_t d;
  _Bool e;
} f;
void g(f *b) {
  for (uint32_t c; c < 10; ++c) {
    f *a = &b[c];
  }
}
