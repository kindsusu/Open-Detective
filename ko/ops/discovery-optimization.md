# 제한된 발견 adapter와 오프라인 평가

발견 adapter는 기존 provenance import 흐름을 확장하지만 후보를 소유 자산으로 만들거나 표적 측정을 허가하지 않는다. 공개 channel 작업에는 여전히 정확한 실행 `--scope`, channel별 fresh health, 제한된 로컬 config, 소유자가 통제하는 locator store가 필요하다. 결과의 opaque `locator_ref`도 `probe`나 `browser` 연결 전 소유 증거와 새 scope 판단이 필요하다.

`channel-discover`는 현재 두 adapter만 지원한다. `certspotter`는 certificate-transparency 이름을 소유 대조 후보로 처리한다. `generic_json_export`는 수행자가 지정한 query-bound JSON search 또는 export endpoint를 소비하며 native web/document search coverage를 주장하지 않는다. 두 adapter 모두 provider, channel, source, query work ID, 관측 시각, requests, pages, end condition, partial/error 상태, health provenance, opaque candidate reference를 기록한다. 정확한 후보 URL을 공유 출력에 복사하지 않는다.

```bash
open-detective channel-discover --config _local/channel.json --scope _local/scope.json --channel-health _local/channel-health.json --locator-store _local/locators.sqlite --output _local/channel-result.json
open-detective channel-discover --config _local/channel.json --scope _local/scope.json --channel-health _local/channel-health.json --locator-store _local/locators.sqlite --output _local/channel-result.json --plan _local/search-plan.json --import-output _local/search-plan-import.json
open-detective discovery-eval --input _local/evaluation.json --output _local/evaluation-result.json
open-detective asset-graph --input _local/asset-records.json --previous _local/asset-graph.previous.json --output _local/asset-graph.json
```

channel config는 versioned local operator input이다. provider(`certspotter` 또는 `generic_json_export`), 허용 channel(`certificate_transparency`, `web`, `documents`), opaque source ID, query work ID/value, endpoint shape, 필수 expected control ID, hard request/page/body/candidate limit을 선언한다. 실행은 선언한 expected control ID와 일치할 때만 health provenance를 받는다. provider 결과가 0행이어도 선언한 end condition과 coverage가 뒷받침하지 않으면 complete가 아니다. failed·stale·partial channel은 공백으로 남고 그 상태로 search plan에 import할 수 있다.

report의 `search_plan_import`에는 안전한 health provenance만 남긴다. `--plan`과 `--import-output`을 함께 주면 `channel-discover`가 live report를 정확한 private-plan work ID, query digest, `observed_at` 시점 health와 대조한 뒤 전체 health report가 든 private import payload를 쓴다. synthetic report는 이 payload를 만들 수 없다. 기존 private plan-import 흐름에 payload를 넘기며 수동으로 합성하지 않는다.

`discovery-eval`은 오프라인이다. versioned dataset은 candidate ID, 비용, 순서, 선언한 train/test split, family label, known positive, known false positive, unlabeled unknown을 고정한다. 같은 예산에서 baseline/proposed 순서를 비교해 recall@budget을 보고하고 precision은 labeled positive/known false positive에 대해서만 계산하며 unknown은 별도로 낸다. 이는 평가 artifact일 뿐 회사 발견·소유·channel health·실제 recall 증거가 아니다. 다른 회사와 유사 이름 negative를 넣고 evaluator 결과로 소유를 자동 확정하지 않는다.

asset graph는 owner 제공 CMDB, cloud, IdP snapshot과 normalized discovery record를 reconcile한다. snapshot provenance, 명시적 ownership reference, relationship edge, diff, scope-completion gap을 보존해야 한다. source 부재, cursor gap, permission failure, 불완전 export는 음성 자산 주장 대신 공백으로 남긴다.
