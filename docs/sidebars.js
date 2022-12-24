const sidebars = {
  sidebar: [
    {
      type: "category",
      label: "ZIO Crypto",
      collapsed: false,
      link: { type: "doc", id: "index" },
      items: [ 
        "secure-random",
        "hash",
        "hmac",
        "symmetric-encryption",
        "signature"
      ]
    }
  ]
};

module.exports = sidebars;
