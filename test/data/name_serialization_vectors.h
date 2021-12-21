/*
 * Types
 */

typedef struct name_serializtion_vector {
  char *name;
  uint8_t expected_data[24];
  size_t expected_len;
  bool success;
  char *parsed;
} name_serializtion_vector_t;


/*
 * Vectors
 */

static const name_serializtion_vector_t name_serializtion_vectors[] = {
  {
    "abcdef.",
    {
      0x06, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x00
    },
    8,
    true,
    "abcdef."
  },
  {
    "abc.def.",
    {
      0x03, 0x61, 0x62, 0x63, 0x03, 0x64, 0x65, 0x66, 0x00
    },
    9,
    true,
    "abc.def."
  },
  {
    "abcdef\\000.",
    {
      0x07, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x00, 0x00
    },
    9,
    true,
    "abcdef\\000."
  },
  {
    "abcdef\\255.",
    {
      0x07, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0xff, 0x00
    },
    9,
    true,
    "abcdef\\255."
  },
  {
    "abcdef\\256.",
    {},
    0,
    false, // bad escape (value > 0xff)
    NULL
  },
  {
    "abcdef\\LOL.",
    {
      0x09, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x4c, 0x4f, 0x4c, 0x00
    },
    11,
    true,
    "abcdefLOL."
  },
  {
    "abc\\031def.",
    {
      0x07, 0x61, 0x62, 0x63, 0x1f, 0x64, 0x65, 0x66, 0x00
    },
    9,
    true,
    "abc\\031def."
  },
  {
    "abc\\\\def.",
    {
      0x07, 0x61, 0x62, 0x63, 0x5c, 0x64, 0x65, 0x66, 0x00
    },
    9,
    true,
    "abc\\\\def."
  },
  {
    "\\999.",
    {},
    0,
    false, // bad escape (value > 0xff)
    NULL
  },
  {
    "\\\\999.",
    {
      0x04, 0x5c, 0x39, 0x39, 0x39, 0x00
    },
    6,
    true,
    "\\\\999."
  },
  {
    "\\\\222.",
    {
      0x04, 0x5c, 0x32, 0x32, 0x32, 0x00
    },
    6,
    true,
    "\\\\222."
  },
  {
    "abc\\\\999.",
    {
      0x07, 0x61, 0x62, 0x63, 0x5c, 0x39, 0x39, 0x39, 0x00
    },
    9,
    true,
    "abc\\\\999."
  },
  {
    "abc\\\\99.",
    {
      0x06, 0x61, 0x62, 0x63, 0x5c, 0x39, 0x39, 0x00
    },
    8,
    true,
    "abc\\\\99."
  },
  {
    "abc\\\\.",
    {
      0x04, 0x61, 0x62, 0x63, 0x5c, 0x00
    },
    6,
    true,
    "abc\\\\."
  },
  {
    "\\..",
    {
      0x01, 0x2e, 0x00
    },
    3,
    true,
    "\\.."
  },
  {
    "\\046.",
    {
      0x01, 0x2e, 0x00
    },
    3,
    true,
    "\\.."
  }
};
