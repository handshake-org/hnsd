/*
 * Types
 */

typedef struct name_serializtion_vector {
  char *name;
  uint8_t expected_data[256];
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
  },
  {
    // Longest possible printable DNS name
    // where all bytes are unprintable characters.
    // ((63 * 4) + 1) + ((61 * 1) + 1)
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031."
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031."
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031."
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031.",
    {
      0x3f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x3f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x3f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x3d,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x00
    },
    255,
    true,
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031."
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031."
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031."
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031.",
  },
  {
    // Exceed max name length (last label has 62, total 256)
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031."
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031."
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031."
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031.",
    {
      0x3f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x3f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x3f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x3e,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x00
    },
    256,
    false,
    NULL
  },
  {
    // Exceed max label length (only one label, has 64)
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031"
    "\\031\\031\\031\\031\\031\\031\\031\\031.",
    {
      0x40,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
      0x00
    },
    66,
    false,
    NULL
  }
};
