package com.example.SpringBootDemo.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.oracle.tools.packager.Log;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.example.SpringBootDemo.utils.*;

@RestController
public class IndexController {

    private String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5FFi6s3lsSDPk0zRY7Aio3ozieZUtNUjhFB+90U9uT3ROoMZ+IprQT2mfaFYJpcelxuWIl35jEixjB9nRCHwhB5dvHr2/QzYQuNL+Qbu3KB3eSE6NRggsTILgXt1kbGFdYrrVpfbT2Qc/i4zFaqBNwr10wei99yYPJwwipJ5ruwIDAQAB";

    private String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL5H2UdKuY6CuZ8QoPiQx/gErtErXYXVeiAu3lu68TVjq6n0YGdOG3hUFKC77k2zQKnUjjC1WBjyiVt11uInNa7HxwcoEAyPw/nkJzS2mBmGwwyb0yCTNP3NaIMB8zYBGq0pultTaVYIIj8suOoGOrf/TF00+kO9HwruouIMJy4XAgMBAAECgYEAqKxqOF9OM71ALHgCKbW1/e6wxSzK36uIceT6KZiC38/1yVee6ZR8l2L5Ui6lpW0kAigwz47BhIPjLRc9oAYf98A1Ff20DAGqJUiZvh7DRw8vOLipItkC1gPCnI65/FV7JzKC2OHAd/4Tv+4Tpd4lbPKycxtAgkErFB59YaORLAkCQQD6IXxTF75f9GldSHYlvjjap5QluufJqC9ZNm1D3BqF7y9WJURb/iCguC0x+V1skvIg+ARlwoSejYPfi9l/Le0jAkEAwr7ZMMkBqvgxg2yNutyTQovq/15vF+H45BftFOJZ/+Ou8ZPnEZsDI+FbL8rDooUlSJQ+PTZEo9tqb4w2ZZxMfQJAKF1fAsnCHxoCJtuatVyNMDv63FvdK93IRk1SNLFAVnzS1sQM1AuemFEgegAT44GTMV7U1tcdL7kGnvyijLOMoQJAPPO+xqYi/3/u/1NaiMHA1XM1eff0jWUMoVdbvM2bnZuFhdbk233I3dIK2Ep+ML+7i5vaXw49LYvfJEqeO+9PgQJAa+h7ruj53mOUaHkfLMYqZ9fGJxJ+YVwMZtbkyxUSJw6Wef2OoWLwlAzoB1IMLx4JY1EyLfGhR+lOQI2kdVrUqA==";

    private String aesKey;

    private String desKey;

    @PostMapping("/index")
    public byte[] index(@RequestBody byte[] data) throws Exception {


        byte[] bytes = RSAUtils.decryptByPrivateKey(data, privateKey);
        String jsonStr = new String(bytes);
        JSONObject jsonObject = JSON.parseObject(jsonStr);

        aesKey = jsonObject.getString("aesKey");
        desKey = jsonObject.getString("desKey");

        Log.debug("RSA Request: " + jsonStr);

        String responseStr = "RSA response ok";
        Log.debug("RSA Response: " + responseStr);
        byte[] bytes1 = RSAUtils.encryptByPublicKey(responseStr.getBytes(), publicKey);
        return bytes1;
    }

    @PostMapping("/aes")
    public byte[] aes(@RequestBody byte[] data) throws Exception {

        byte[] bytes = AES.decrypt(data, aesKey);
        Log.debug("AES Request: " + new String(bytes));

        String responseStr = "aes response ok";
        byte[] bytes1 = AES.encrypt(responseStr.getBytes(), aesKey);

        return bytes1;
    }

    @PostMapping("/des")
    public byte[] des(@RequestBody byte[] data) throws Exception {
        byte[] bytes = DES.decrypt(data, desKey);
        Log.debug("Client Send: " + new String(bytes));

        String responseStr = "des response ok";
        Log.debug("Server Response: " + responseStr);

        return DES.encrypt(responseStr.getBytes(), desKey);
    }
}
