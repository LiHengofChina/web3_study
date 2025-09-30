package com.liheng.demo_002.bouncy_castle.test_002_pgp.ecc.spring_boot;


import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class GatewayApplication {

    @Autowired
    private PgpService pgpService;

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    // ������ܺͽ����߼�
    @Autowired
    public void runPgpOperations() {

    	try {
            // ��1�� ���ַ�����ȡ��Կ
            PGPPublicKey publicKey = pgpService.readPublicKeyFromString();
            if (publicKey.getAlgorithm() != PGPPublicKey.ECDH) {
                throw new IllegalArgumentException("The provided public key is not suitable for encryption.");
            }

            // ��2�� ��������
            String originalData = "{\"taskId\":\"7b83bea3-758b-11ef-b1a6-005056a7f4c9\",\"taskType\":0,\"bizMark\":\"lease_approve_flow\"}";
            System.out.println("ԭʼ����: " + originalData);
            byte[] encryptedData = pgpService.encryptData(originalData.getBytes(), publicKey);



            // ��4�� ��������
            byte[] decryptedData = pgpService.decryptData(encryptedData);
            System.out.println("���ܺ������: " + new String(decryptedData));

        } catch (PGPException | IOException e) {
            System.err.println("��������: ");
            e.printStackTrace();
        }
    }
}
