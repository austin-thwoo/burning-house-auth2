#!/bin/bash
echo "==========================="
echo "       공통단 버전관리        "
echo "==========================="
cd ../src/main/java
globalcommon=(`ls -a | grep 'globalCommon'`)
if [ -z ${globalcommon} ]; then
  echo "공통단 없음 - 공통단 생성"
  mkdir globalCommon
fi
cd globalCommon
ls=(`ls -a | grep '.git'`)
if [ -z ${ls} ]; then
  echo "공통단 git 관리 되지 않음 - 삭제 후 클론"
  cd ..
  rm -rf globalCommon
  echo "공통단 clone"
  git clone https://github.com/austin-thwoo/globalCommon.git
else
  echo "공통단 git 관리 중 - 기존 사용"
  echo "공통단 pull"
  git pull https://github.com/austin-thwoo/globalCommon.git
fi
echo "모든 작업이 종료되었습니다."