package com.liheng.demo_001.java_jwt.signature.asymmetric_key.test_002_ecc;
//
////==================================================================== ���½ start
////==================================================================== ���½ start
//import { KJUR } from 'jsrsasign';  // �� jsrsasign �⵼�������ģ��
//
//
////JWT ��֤����
//function verifyJWT(token) {
//  try {
//
//      const pemPublicKey = store.getters['auth/pemPublicKey'];  // ��ȡ��Կ
//      // ʹ�� jsrsasign �� verifyJWT ����֤ JWT ����Ч��
//      const isValid = KJUR.jws.JWS.verifyJWT(token, pemPublicKey, {
//          alg: ['ES256'], 
//      });
//
//      if (isValid) {
//          const decoded = KJUR.jws.JWS.parse(token);  // ���� JWT ��ȡ������
//          // console.log('Decoded payload:', decoded.payloadObj);  // ��ӡ�����������
//          return decoded.payloadObj;  // ���ؽ������ JWT ����
//      } else {
//          console.error('Invalid JWT.');
//          return null;
//      }
//  } catch (err) {
//      console.error('Error verifying JWT:', err.message);
//      return null;
//  }
//}
//import store from '@/store';  // ���� Vuex store ʵ��
///**
//* ȫ��·������
//*/
//router.beforeEach((to, from, next) => {
//  const requestURI = to.path;  // ��ȡ����� URI
//  // �� '////' ��ͷ
//  if (requestURI.startsWith('////')) {
//
//      showLoadingIndicator();  // �������ض���
//
//      const token = requestURI.slice(4); // ��ȡ��ǰ��� '////'
//      if (token) {
//          const decoded = verifyJWT(token);
//          if (decoded) { // JWT ��֤ͨ������������������������·��
//
//              //�޸�
//              store.dispatch('auth/updateExemptionfromlogin', true);
//              next(decoded.sub);  // `sub` �ֶΰ���ԭʼ�����·��
//          } else {
//              console.error('Invalid or missing JWT. Redirecting to login.');
//          }
//      }
//
//      hideLoadingIndicator();  // ��֤������رռ��ض���
//
//  } else {
//      next();
//  }
//});
//
//function showLoadingIndicator() {
//  // ��ʾ���ض������߼���������һ��ȫ�� loading ���
//  // TODO
//}
//
//function hideLoadingIndicator() {
//  // ���ؼ��ض������߼�
//  // TODO
//}
//
////==================================================================== ���½ end
////==================================================================== ���½ end
