========================================
           PAM MODULE README
========================================

[1] 프로젝트 개요
-------------------
이 프로젝트는 Linux PAM(Pluggable Authentication Module) 기반의 인증 모듈입니다.
SSH, su, sudo 등의 인증 과정에서 추가적인 보안 정책을 적용할 수 있습니다.

[2] 프로젝트 구조
-------------------
- src/               -> 소스 코드 폴더
  ├── pam_module.c   -> PAM 모듈 구현 파일
  ├── pam_module.h   -> 헤더 파일
  ├── Makefile       -> 빌드 및 설치 스크립트
  ├── test/          -> 테스트 데이터 및 스크립트
  ├── docs/          -> 문서 및 가이드
  ├── config/        -> PAM 설정 파일 예제
  ├── scripts/       -> 설치 및 제거 스크립트
  ├── README.txt     -> 프로젝트 설명 파일 (현재 파일)
  ├── LICENSE        -> 라이선스 정보

[3] 설치 방법
-------------------
1. 소스 코드 컴파일:
   $ make

2. PAM 모듈 설치:
   $ sudo make install

3. PAM 설정 적용:
   /etc/pam.d/sshd 파일을 수정하여 다음 줄 추가:
   auth required /lib/security/pam_module.so

4. SSH 서비스 재시작:
   $ sudo systemctl restart sshd

[4] 구성 및 설정
-------------------
PAM 모듈을 적용하려면 /etc/pam.d/ 내부의 서비스 설정 파일을 수정해야 합니다.

예제:
   auth required pam_unix.so
   auth required /lib/security/pam_module.so

환경 변수 설정:
   export PAM_MODULE_PATH=/lib/security/pam_module.so

[5] 사용 방법
-------------------
1. SSH 또는 su 명령 실행 후 PAM 모듈이 적용되었는지 확인합니다.
2. 로그 확인:
   $ sudo tail -f /var/log/auth.log  (Ubuntu/Debian)
   $ sudo tail -f /var/log/secure    (RHEL/CentOS)

[6] 로그 및 디버깅
-------------------
PAM 모듈의 동작을 확인하려면 syslog를 활성화해야 합니다.

실시간 로그 확인:
   $ sudo journalctl -xe | grep pam_module

[7] 제거 방법
-------------------
$ sudo make uninstall

[8] 라이선스
-------------------
이 프로젝트는 MIT License에 따라 배포됩니다.

========================================
      END OF README
========================================
