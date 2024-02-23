import { decrypt, getPubKeyPoint, toPrivKeyECC } from "@tkey-mpc/common-types";
import base64url from "base64url";

import { TorusStorageLayer } from "../src";

describe("test", function () {
  it("should work", async function () {
    [twitter1, email, twitter2].forEach(async (key) => {
      datas.forEach(async (data) => {
        const encryptedMessage = JSON.parse(base64url.decode(data));
        console.log(encryptedMessage);

        console.log(key.length);
        try {
          const decrypted = await decrypt(toPrivKeyECC(key), encryptedMessage);
          console.log(decrypted);
        } catch (error) {
          console.log(error);
        }
      });
    });

    [twitter1, email, twitter2].forEach(async (key) => {
      console.log(`publicKey x`, getPubKeyPoint(key).x);
    });

    const storage = new TorusStorageLayer({
      hostUrl: "https://metadata.tor.us",
    });
    const data = await storage.getMetadata({ privKey: twitter1 });
    console.log(data);
    const data1 = await storage.getMetadata({ privKey: email });
    console.log(data1);
    const data2 = await storage.getMetadata({ privKey: twitter2 });
    console.log(data2);
  });
});
