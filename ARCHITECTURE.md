# Angie Guardian: Architecture

How Guardian fits into Angie, and what it does on and off the request path.
For an overview of the project see the [README](README.md); for configuration
and operations see [USAGE.md](USAGE.md) and <https://angieguardian.org/>.

## Live request path

Angie remains in the request path and keeps serving the site's existing static,
`try_files`, FastCGI, or reverse-proxy handler. Guardian is a sidecar decision
service: Angie sends it a bodyless internal authorization subrequest and acts on
the resulting allow, challenge, or deny response.

```plantuml
@startuml
skinparam backgroundColor #F8FAFC
skinparam shadowing false
skinparam roundCorner 12
skinparam defaultFontName Sans-Serif
skinparam sequence {
  ArrowColor #2563EB
  LifeLineBorderColor #475569
  LifeLineBackgroundColor #F8FAFC
  ParticipantBorderColor #475569
  ParticipantBackgroundColor #F8FAFC
  ParticipantFontColor #0F172A
  ActorBorderColor #475569
  ActorFontColor #0F172A
  GroupBorderColor #64748B
  GroupFontColor #0F172A
}
hide footbox

title Angie Guardian - Live Request Path
actor "Visitor/Bot" as Client
participant "Angie vhost" as Angie
participant "guardiand" as Guardian
participant "Original site handler\n(backend)" as Backend

Client -[#2563EB]> Angie: Request
Angie -[#2563EB]> Guardian: Can this request continue?

alt ALLOW
  Guardian -[#15803D]> Angie: Allow
  Angie -[#15803D]> Backend: Continue to the site
  Backend -[#15803D]> Client: Site response
else CHALLENGE
  Guardian -[#D97706]> Angie: Challenge
  Angie -[#D97706]> Client: Proof-of-work page
  Client -[#D97706]> Angie: Solve challenge
  Angie -[#D97706]> Guardian: Verify solution
  Guardian -[#D97706]> Angie: Grant signed pass
  Angie -[#D97706]> Client: Signed pass
  Client -[#15803D]> Angie: Retry original request
  Angie -[#15803D]> Guardian: Check signed pass
  Guardian -[#15803D]> Angie: Allow
  Angie -[#15803D]> Backend: Continue to the site
  Backend -[#15803D]> Client: Site response
else DENY
  Guardian -[#B91C1C]> Angie: Deny
  Angie -[#B91C1C]> Client: Block request
else GUARDIAN UNAVAILABLE - FAIL OPEN
  Angie -[#15803D]> Backend: Continue to the site
  Backend -[#15803D]> Client: Site response
end

note over Angie, Backend #E8F5E9
  Remove the fail-open error_page mapping to choose fail-closed.
end note

@enduml
```

## Policy, state, training, and operations

The same sidecar loads policy and key material, owns stateful protection, and
exposes a separate operations listener. Offline training and optional
integrations feed this supporting plane without sitting in the live request
path.

```plantuml
@startuml
skinparam backgroundColor transparent
skinparam shadowing false
skinparam roundCorner 12
skinparam defaultFontName Sans-Serif
skinparam ArrowFontSize 11
skinparam activity {
  BorderColor #475569
  FontColor #0F172A
  BackgroundColor #F8FAFC
}
skinparam partition {
  BorderColor #475569
  FontColor #0F172A
}

partition #F5F3FF "Angie Guardian - Policy, State, Training, and Operations" {
  start

  if (Integration path?) then (full sidecar)
    fork
      -[#64748B,dashed]->
      :<b>Load policy</b>\nConfig, WAF rules, keys, and threat data; <<#F8FAFC>>
    fork again
      -[#2563EB]->
      :<b>Optional offline training</b>\nAccess logs -> anomaly model; <<#DBEAFE>>
    end fork

    -[#2563EB]->
    :<b>Activate a validated snapshot</b>\nKeep the last good version if reload fails; <<#FFF7E6>>

    fork
      -[#64748B,dashed]->
      :<b>Stateful protection</b>\nBlocks, challenges, and counters; <<#F1F5F9>>
    fork again
      -[#7C3AED]->
      :<b>Operations</b>\nDashboard, API, health, and metrics; <<#F8FAFC>>
    fork again
      -[#B91C1C,dashed]->
      :<b>Optional nftables</b>\nDrop known blocks before Angie; <<#FDECEC>>
    end fork
    stop
  else (optional WASM alternative)
    -[#9333EA,dashed]->
    :<b>Run stateless policy inside Angie</b>\nStore-free WAF only; no PoW or shared state; <<#F3E8FF>>
    stop
  endif
}

@enduml
```
