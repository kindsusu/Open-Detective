# 노출면 인벤토리

제한된 커버리지를 표현하는 체크리스트다. 모든 provider나 asset을 찾았다는 주장이 아니다.

| 노출면 | 소유자 인벤토리 | 공개 보완 | 완료 증거 |
|---|---|---|---|
| Source/deployment | GitHub organization/account repository와 선택적 tree; Vercel scope의 project, deployment, alias, domain | owner 제공 normalized Pages/environment record, passive public repo/deployment record | cursor/page 종료, permission, truncation, time window |
| DNS/TLS | managed zone, registrar, certificate inventory | CT, public DNS | zone/scope 목록과 observation time |
| Static/CDN hosting | provider project, origin, alias | public URL, header | project/alias relationship 완료 |
| Object storage | owner bucket/container inventory와 policy | exact public link. 이름만으로 probing 안 함 | account scope와 policy retrieval 완료 |
| Document/share | admin 승인 Drive/SharePoint/Box export | public search/share link | tenant/export scope와 retrieval time |
| SaaS/low-code | workspace app, published page, integration | public app URL | workspace/project scope와 permission gap |
| AI/public collaboration | 가능한 owner/admin share inventory | indexed public share URL | provider limitation과 date |
| Package/artifact | registry, release, build artifact, image | public registry metadata | namespace와 pagination 완료 |
| Operations surface | CMDB/cloud inventory | public metadata만. 승인 없이 port/service 상호작용 안 함 | owner approval과 exact endpoint |
| Archive/cache | 승인된 channel의 known snapshot/cache | archive index | queried collection/time range |

owner type은 organization, employee/former-employee personal, third party, unknown으로 추적한다. 조직 소유도 정책에 선언한 측정만 허용한다. 개인·제3자 자료는 승인된 takedown/notification으로 처리하며 유사성이 접근을 넓히지 않는다.

이 인벤토리 전에 `examples/audit-intake.example.json`, `schemas/audit-intake.schema.json`으로 로컬 audit intake를 만든다. 관계사 경계와 제3자를 `provided`, `unknown`, `none_declared`로 기록한다. `unknown`은 공백으로 남기며 추측으로 조직 소유가 되지 않는다. 계약·자산·처리자·수탁자의 관리자 export를 받은 뒤 실행 scope를 승인하고 candidate를 import한다. intake는 scope가 아니며 네트워크 요청을 허가하지 않는다.

확증된 ownership link, possible data impact, 최근 deployment/change, request/privacy cost 대비 expected information gain처럼 책임 있게 설명할 수 있는 증거로 우선순위를 정한다. 조직별 발생확률을 하드코딩하거나 어떤 범주를 확실하다고 표현하지 않는다. 분리된 brand, affiliate, 비개발자 도구에도 예산을 남긴다.

각 행에 `source`, `retrieved_at`, `owner_scope`, `relationship`, `ownership_evidence`, `completeness`, `gap_reason`, `source_record_id`, `next_cursor`를 기록한다. private source repository가 private deployed site를 뜻하지 않는다. public UI가 sensitive content를 뜻하지 않는다.

제외에는 exact URL, 문서화한 게시 의도, owner/evidence, review date가 필요하다. domain 전체 제외는 의도하지 않은 path를 숨길 수 있다.
