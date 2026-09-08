# 격리, 복구, 재측정

확정 증거와 현재 피해를 기준으로 조치를 고른다. 현재 개인정보나 비밀 노출이면 긴급 격리와 로그 보존이 연속성 작업보다 앞설 수 있다. 현재 피해가 없는 계획 이전이면 대체 경로를 먼저 준비할 수 있다. 하나의 고정 순서를 적용하지 말고 이유를 기록한다.

## 조치 계획

1. 증거 참조를 고정하고 노출 내용을 복제하지 않으면서 필요한 provider/application log를 보존한다.
2. 정확한 public deployment, share, object, alias를 제한/삭제하고 다른 alias 연결을 확인한다.
3. 확정된 private secret을 소유자 통제 시스템에서 회전한다. audit code는 시험하거나 사용하지 않는다.
4. 연속성이 필요하면 검토된 private deployment로 서비스를 복구한다.
5. SSO나 edge access gate 뒤에서도 server-side user, role, tenant, object authorization을 유지한다. SSO authentication은 application authorization이 아니다.
6. 제한된 노출 기간의 owner-side access log를 보고 privacy/legal 판단을 책임자에게 보낸다.
7. 새 익명 context로 원 locator와 알려진 모든 deployment/alias를 재확인한다. 허용된 cache와 archive는 별도로 확인한다.

repository private 전환이 예전 deployment, fork, package release, build artifact, copied file을 제거한다고 가정하지 않는다. 대응에 필요한 log를 삭제하지 않는다. 격리가 큰 outage를 만들면 tradeoff를 명시해 에스컬레이션한다. 현재 피해가 크면 즉시 격리가 여전히 필요할 수 있다.

## 종결

`closed`에는 알려진 모든 live locator에서 기대하는 access/content 상태를 보이는 새 observation evidence와 선언한 residue scope 완료가 필요하다. target/policy binding은 등록된 원 locator와 alias에 일치해야 한다. live access는 막혔지만 archive/cache/deployment coverage가 불완전하면 `partially_closed`다. 종결 뒤 현재 `BODY_SERVED`, unknown/incomplete observation, 같은 시각 충돌은 finding을 재검토 상태로 돌린다. digest 변화만으로는 부족하다.

owner, action due date, recheck due date, backoff/retry policy, escalation route를 정한다. 변화 없는 observation은 조용히 둘 수 있지만 overdue, failed, reopened, user-action-required event는 보여야 한다.
