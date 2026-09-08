# 승인된 로컬 포렌식 증거

포렌식은 익명 측정 및 운영 SQLite 대장과 분리한다. 승인된 로컬 case 파일과 소유자가 승인한 read-only 로컬 export만 다룬다. 측정 `--scope`는 제한된 익명 HTTP 관측만 허가하며 case 생성, export 획득, 증거 보존, 포렌식 분석을 허가하지 않는다.

case 파일, source export, 획득 artifact, manifest, custody chain, timeline은 소유자가 통제하는 로컬 디렉터리에 두고 commit하지 않는다. case에는 목적·보존 참조, 기간이 있는 authorization 참조, 승인된 read-only collector, 정확한 allowed source를 기록한다. 이 흐름으로 로그인, credential 재사용, 통제 우회, 인접 레코드 열거, RAM/disk image 획득을 하지 않는다. 이번 구현은 소유자가 제공한 `normalized_event_jsonl` export만 받으며 disk/RAM image와 vendor format import는 범위 밖이다.

```bash
python -m sudetect forensics acquire --case _local/case.json --source-id src_00000000000000000000000000000005 --export _local/export.jsonl --evidence-dir _local/evidence
python -m sudetect forensics verify --manifest _local/evidence/<evidence-id>/manifest.json --evidence-dir _local/evidence
python -m sudetect forensics custody-add --case _local/case.json --chain _local/evidence/custody.jsonl --event _local/event.json --evidence-dir _local/evidence
python -m sudetect forensics custody-verify --chain _local/evidence/custody.jsonl --expected-head "<승인된 별도 보관 head hash>"
python -m sudetect forensics timeline --case _local/case.json --events _local/events.jsonl --evidence-dir _local/evidence --output _local/timeline.json
python -m sudetect forensics timeline-verify --timeline _local/timeline.json --evidence-dir _local/evidence
```

명령은 안전한 JSON 요약만 stdout에 내며 source content를 복사하지 않아야 한다. hash는 획득한 byte stream의 이후 변경을 탐지하지만 artifact의 진본성, 소유, 법적 증거능력, 완전한 custody를 보장하지 않는다. custody-add에 `--evidence-dir`를 주면 참조 manifest/artifact와 case를 검증하며, 없으면 custody reference는 self-reported다. 외부에 보관한 `--expected-head` 없이 custody chain을 검증하면 내부 link는 확인할 수 있어도 모든 tail truncation·full rehash를 탐지할 수 없다. source 제공 provenance, collector identity, authorization reference, event time, ingest time, clock uncertainty, retention gap, 수집 side effect를 분리해 기록한다. 원본을 보존하고 필요할 때만 통제된 redacted derivative를 공유한다. timeline 입력은 `normalized_event_jsonl` type의 획득된 allowed source만 허용하며 각 행은 일치하는 source·evidence·event time·canonical raw-line hash reference를 보존해야 한다.

`verify`, `timeline-verify`, custody 검증은 과거 artifact의 무결성만 확인한다. 현재 수집 권한이나 보존 기간 승인을 갱신하지 않는다. 오래된 custody lock을 자동으로 지우지 말고 case 소유자가 확인한 뒤 해제한다. 로컬 hash와 연결 record는 case 디렉터리 전체를 다시 쓸 수 있는 사람에 대한 방어를 주장하지 않는다.

없거나, 만료됐거나, 접근 불가하거나, unknown인 log는 coverage gap이다. event·actor·exfiltration이 없었다는 증거가 아니다. 공개 접근 관측과 exfiltration 증명은 별도 주장이다. timeline join에는 evidence reference와 불확실성을 남기며 연속된 순서나 actor attribution을 만들어 내지 않는다.

live SaaS, mail, EDR, cloud-IAM, storage, application-access, deployment, DLP, endpoint collector, vendor parser, backend authorization-policy test는 구현하지 않았다. 소유자가 통제하는 승인된 수집 절차로 export를 얻은 뒤 이 로컬 normalized-input 흐름을 사용한다.

이 흐름은 [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final)의 collection·examination·analysis·reporting 구조와 [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)의 preparation·detection·response·recovery 관행을 참고한다. 이 자료는 권한을 부여하거나 법적 증거능력을 보장하지 않는다.
