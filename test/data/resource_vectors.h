#include "resource.h"

/*
 * Types
 */

typedef struct type_vector {
  uint16_t type;
  char *type_string;
  uint8_t an_size;
  uint8_t ns_size;
  uint8_t ar_size;
  bool nsec;
  bool aa;
} type_vector_t;

typedef struct resource_vector {
  char *name;
  uint8_t data[255];
  uint8_t data_len;
  type_vector_t type_vectors[4];
  // Expected in NSEC records
  size_t type_map_len;
  const uint8_t *type_map;
} resource_vector_t;

/*
 * Vectors
 */

static const resource_vector_t resource_vectors[] = {
  // {
  //   "records": [
  //     {
  //       "type": "SYNTH4",
  //       "address": "50.60.70.80"
  //     }
  //   ]
  // }
  {
    "test-synth4.",
    {
      0x00, 0x04, 0x32, 0x3c, 0x46, 0x50
    },
    6,
    {
      {HSK_DNS_DS,  "DS",  0, 4, 0, true, true},
      {HSK_DNS_NS,  "NS",  0, 3, 1, true, false},
      {HSK_DNS_TXT, "TXT", 0, 3, 1, true, false},
      {HSK_DNS_A,   "A",   0, 3, 1, true, false}
    },
    sizeof(hsk_type_map_ns),
    hsk_type_map_ns
  },

  // {
  //   "records": [
  //     {
  //       "type": "SYNTH6",
  //       "address": "8888:7777:6666:5555:4444:3333:2222:1111"
  //     }
  //   ]
  // }
  {
    "test-synth6.",
    {
      0x00, 0x05, 0x88, 0x88, 0x77, 0x77, 0x66, 0x66, 0x55, 0x55, 0x44, 0x44,
      0x33, 0x33, 0x22, 0x22, 0x11, 0x11
    },
    18,
    {
      {HSK_DNS_DS,  "DS",  0, 4, 0, true, true},
      {HSK_DNS_NS,  "NS",  0, 3, 1, true, false},
      {HSK_DNS_TXT, "TXT", 0, 3, 1, true, false},
      {HSK_DNS_A,   "A",   0, 3, 1, true, false}
    },
    sizeof(hsk_type_map_ns),
    hsk_type_map_ns
  },

  // {
  //   "records": [
  //     {
  //       "type": "GLUE4",
  //       "ns": "ns2.hns.",
  //       "address": "10.20.30.40"
  //     }
  //   ]
  // }
  {
    "test-glue4.",
    {
      0x00, 0x02, 0x03, 0x6e, 0x73, 0x32, 0x03, 0x68, 0x6e, 0x73, 0x00, 0x0a,
      0x14, 0x1e, 0x28
    },
    15,
    {
      {HSK_DNS_DS,  "DS",  0, 4, 0, true, true},
      {HSK_DNS_NS,  "NS",  0, 3, 0, true, false},
      {HSK_DNS_TXT, "TXT", 0, 3, 0, true, false},
      {HSK_DNS_A,   "A",   0, 3, 0, true, false}
    },
    sizeof(hsk_type_map_ns),
    hsk_type_map_ns
  },

  // {
  //   "records": [
  //     {
  //       "type": "GLUE4",
  //       "ns": "ns2.test-glue4-glue.",
  //       "address": "10.20.30.40"
  //     }
  //   ]
  // }
  {
    "test-glue4-glue.",
    {
      0x00, 0x02, 0x03, 0x6e, 0x73, 0x32, 0x0f, 0x74, 0x65, 0x73, 0x74, 0x2d,
      0x67, 0x6c, 0x75, 0x65, 0x34, 0x2d, 0x67, 0x6c, 0x75, 0x65, 0x00, 0x0a,
      0x14, 0x1e, 0x28
    },
    27,
    {
      {HSK_DNS_DS,  "DS",  0, 4, 0, true, true},
      {HSK_DNS_NS,  "NS",  0, 3, 1, true, false},
      {HSK_DNS_TXT, "TXT", 0, 3, 1, true, false},
      {HSK_DNS_A,   "A",   0, 3, 1, true, false}
    },
    sizeof(hsk_type_map_ns),
    hsk_type_map_ns
  },

  // {
  //   "records": [
  //     {
  //       "type": "GLUE6",
  //       "ns": "ns2.hns.",
  //       "address": "1111:2222:3333:4444:5555:6666:7777:8888"
  //     }
  //   ]
  // }
  {
    "test-glue6.",
    {
      0x00, 0x03, 0x03, 0x6e, 0x73, 0x32, 0x03, 0x68, 0x6e, 0x73, 0x00, 0x11,
      0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77,
      0x77, 0x88, 0x88
    },
    27,
    {
      {HSK_DNS_DS,  "DS",  0, 4, 0, true, true},
      {HSK_DNS_NS,  "NS",  0, 3, 0, true, false},
      {HSK_DNS_TXT, "TXT", 0, 3, 0, true, false},
      {HSK_DNS_A,   "A",   0, 3, 0, true, false}
    },
    sizeof(hsk_type_map_ns),
    hsk_type_map_ns
  },

  // {
  //   "records": [
  //     {
  //       "type": "GLUE6",
  //       "ns": "ns2.test-glue6-glue.",
  //       "address": "1111:2222:3333:4444:5555:6666:7777:8888"
  //     }
  //   ]
  // }
  {
    "test-glue6-glue.",
    {
      0x00, 0x03, 0x03, 0x6e, 0x73, 0x32, 0x0f, 0x74, 0x65, 0x73, 0x74, 0x2d,
      0x67, 0x6c, 0x75, 0x65, 0x36, 0x2d, 0x67, 0x6c, 0x75, 0x65, 0x00, 0x11,
      0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77,
      0x77, 0x88, 0x88
    },
    39,
    {
      {HSK_DNS_DS,  "DS",  0, 4, 0, true, true},
      {HSK_DNS_NS,  "NS",  0, 3, 1, true, false},
      {HSK_DNS_TXT, "TXT", 0, 3, 1, true, false},
      {HSK_DNS_A,   "A",   0, 3, 1, true, false}
    },
    sizeof(hsk_type_map_ns),
    hsk_type_map_ns
  },

  // {
  //   "records": [
  //     {
  //       "type": "NS",
  //       "ns": "ns1.hns."
  //     }
  //   ]
  // }
  {
    "test-ns.",
    {
      0x00, 0x01, 0x03, 0x6e, 0x73, 0x31, 0x03, 0x68, 0x6e, 0x73, 0x00
    },
    11,
    {
      {HSK_DNS_DS,  "DS",  0, 4, 0, true, true},
      {HSK_DNS_NS,  "NS",  0, 3, 0, true, false},
      {HSK_DNS_TXT, "TXT", 0, 3, 0, true, false},
      {HSK_DNS_A,   "A",   0, 3, 0, true, false}
    },
    sizeof(hsk_type_map_ns),
    hsk_type_map_ns
  },

  // {
  //   "records": [
  //     {
  //       "type": "NS",
  //       "ns": "ns1.test-ns-glue."
  //     }
  //   ]
  // }
  {
    "test-ns-glue.",
    {
      0x00, 0x01, 0x03, 0x6e, 0x73, 0x31, 0x0c, 0x74, 0x65, 0x73, 0x74, 0x2d,
      0x6e, 0x73, 0x2d, 0x67, 0x6c, 0x75, 0x65, 0x00
    },
    20,
    {
      {HSK_DNS_DS,  "DS",  0, 4, 0, true, true},
      {HSK_DNS_NS,  "NS",  0, 3, 0, true, false},
      {HSK_DNS_TXT, "TXT", 0, 3, 0, true, false},
      {HSK_DNS_A,   "A",   0, 3, 0, true, false}
    },
    sizeof(hsk_type_map_ns),
    hsk_type_map_ns
  },

  // {
  //   "records": [
  //     {
  //       "type": "DS",
  //       "keyTag": 57355,
  //       "algorithm": 8,
  //       "digestType": 2,
  //       "digest": "95a57c3bab7849dbcddf7c72ada71a88146b141110318ca5be672057e865c3e2"
  //     }
  //   ]
  // }
  {
    "test-ds.",
    {
      0x00, 0x00, 0xe0, 0x0b, 0x08, 0x02, 0x20, 0x95, 0xa5, 0x7c, 0x3b, 0xab,
      0x78, 0x49, 0xdb, 0xcd, 0xdf, 0x7c, 0x72, 0xad, 0xa7, 0x1a, 0x88, 0x14,
      0x6b, 0x14, 0x11, 0x10, 0x31, 0x8c, 0xa5, 0xbe, 0x67, 0x20, 0x57, 0xe8,
      0x65, 0xc3, 0xe2
    },
    39,
    {
      {HSK_DNS_DS,  "DS",  2, 0, 0, false, true},
      {HSK_DNS_NS,  "NS",  0, 4, 0, true, true},
      {HSK_DNS_TXT, "TXT", 0, 4, 0, true, true},
      {HSK_DNS_A,   "A",   0, 4, 0, true, true}
    },
    sizeof(hsk_type_map_empty),
    hsk_type_map_empty
  },

  // {
  //   "records": [
  //     {
  //       "type": "TXT",
  //       "txt": [
  //         "hello world",
  //         "how are you"
  //       ]
  //     }
  //   ]
  // }
  {
    "test-txt.",
    {
      0x00, 0x06, 0x02, 0x0b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f,
      0x72, 0x6c, 0x64, 0x0b, 0x68, 0x6f, 0x77, 0x20, 0x61, 0x72, 0x65, 0x20,
      0x79, 0x6f, 0x75
    },
    27,
    {
      {HSK_DNS_DS,  "DS",  0, 4, 0, true, true},
      {HSK_DNS_NS,  "NS",  0, 4, 0, true, true},
      {HSK_DNS_TXT, "TXT", 2, 0, 0, false, true},
      {HSK_DNS_A,   "A",   0, 4, 0, true, true}
    },
    sizeof(hsk_type_map_txt),
    hsk_type_map_txt
  },

  // {
  //   "records": [
  //     {
  //       "type": "DS",
  //       "keyTag": 57355,
  //       "algorithm": 8,
  //       "digestType": 2,
  //       "digest": "95a57c3bab7849dbcddf7c72ada71a88146b141110318ca5be672057e865c3e2"
  //     },
  //     {
  //       "type": "GLUE6",
  //       "ns": "ns1.test-all.",
  //       "address": "4:8:15:16:23:42:108:815"
  //     },
  //     {
  //       "type": "TXT",
  //       "txt": [":-)"]
  //     }
  //   ]
  // }
  {
    "test-all.",
    {
      0x00, 0x00, 0xe0, 0x0b, 0x08, 0x02, 0x20, 0x95, 0xa5, 0x7c, 0x3b, 0xab,
      0x78, 0x49, 0xdb, 0xcd, 0xdf, 0x7c, 0x72, 0xad, 0xa7, 0x1a, 0x88, 0x14,
      0x6b, 0x14, 0x11, 0x10, 0x31, 0x8c, 0xa5, 0xbe, 0x67, 0x20, 0x57, 0xe8,
      0x65, 0xc3, 0xe2, 0x03, 0x03, 0x6e, 0x73, 0x31, 0x08, 0x74, 0x65, 0x73,
      0x74, 0x2d, 0x61, 0x6c, 0x6c, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0x15,
      0x00, 0x16, 0x00, 0x23, 0x00, 0x42, 0x01, 0x08, 0x08, 0x15, 0x06, 0x01,
      0x03, 0x3a, 0x2d, 0x29
    },
    76,
    {
      {HSK_DNS_DS,  "DS",  2, 0, 0, false, true},
      {HSK_DNS_NS,  "NS",  0, 3, 1, false, false},
      {HSK_DNS_TXT, "TXT", 0, 3, 1, false, false},
      {HSK_DNS_A,   "A",   0, 3, 1, false, false}
    },
    0,
    NULL
  }
};
