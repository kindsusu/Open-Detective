# 오프라인 식별자 후보

`tools/idgen.py`는 수행자가 입력한 국문·영문 이름 씨앗을 계정/project/bucket 후보로 순위화해 확장하며 네트워크 요청을 하지 않는다. recall 보조 도구이지 소유 분류기가 아니다.

알고 있다면 공식 로마자 표기를 제공한다. 로마자 변환 결과와 가입에 쓴 철자는 다를 수 있다. 법인격 꼬리는 정규화된 마지막 token일 때만 제거한다. 실행 시 function/industry 값은 NFKC, 소문자, 생성기의 ASCII alphabet으로 정규화한다. 플랫폼 출력에는 namespace별 문자·길이 검증을 적용한다. `--limit`은 양수여야 하고 `--tier`는 1~4다.

```bash
python tools/idgen.py --ko "<이름>" --en "<공식 표기>" --function ops --limit 100
python tools/idgen.py --en "<이름>" --targets vercel --tier 3
python tools/idgen.py --selftest
```

tier 1은 직접 stem, tier 2는 industry affix, tier 3은 generic function affix, tier 4는 numeric suffix다. 여러 단어로 된 공식 영문 표기에서는 입력 단어에 근거한 제한된 복합어 경계(예: `brand-industryword`)와 그 숫자 변형도 보존한다. 순위는 결정론적 검색 순서이며 확률이나 confidence 점수가 아니다. 유한한 `--limit` 안에서 직접 stem과 짧은 숫자 고유화 변형에 먼저 닿도록 넓은 function-word 조합보다 앞에 둔다.

모든 출력은 후보다. owner API, 검증된 DNS/control-plane 관계, repository deployment metadata, 책임 있는 owner record로 확증한다. 유사성, 403/404, 존재하는 account, public page만으로는 부족하다. 확증된 진입점을 찾은 뒤에는 추가 추측보다 team/project/deployment/alias 같은 정확한 relation edge를 우선한다.

실제 회사 씨앗을 저장소에 넣거나, 생성한 값을 모두 probe하거나, 직원 개인 계정을 추론하거나, 비밀 포함 target URL을 저장하지 않는다. 생성기는 네트워크 의존성이 없고 unit test도 오프라인이어야 한다.
