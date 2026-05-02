# AgentsMaestro — Fork notes

> Fork di [slopus/happy](https://github.com/slopus/happy) (MIT) mantenuto da
> **[EngInCoreStudio](https://github.com/EngInCoreStudio)** (Mirko Pelosi — brand EngInCore).

## Identità

- **Nome:** AgentsMaestro
- **Origine:** fork MIT di Happy
- **Owner GitHub:** `EngInCoreStudio` (account personale, brand EngInCore)
- **Repo:** https://github.com/EngInCoreStudio/AgentsMaestro
- **Visione:** interfaccia mobile per controllare agenti AI di coding (Claude Code, Codex)
- **Stato:** fork creato, codice 1:1 con `slopus/happy@main` — vedi PLANNING del workspace genitore per la roadmap

## Differenze rispetto ad upstream

Per ora: **solo questo file**. Il fork tracksa `slopus/happy@main` 1:1.
Le eventuali personalizzazioni saranno annotate in commit con prefisso `[AM]`.

## Sincronizzazione con upstream

```powershell
# Setup remote (già fatto durante il setup iniziale)
git remote add upstream https://github.com/slopus/happy.git

# Pull periodico delle modifiche upstream
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

## Convenzioni di branching

- `main` → segue upstream
- `agentsmaestro/*` → branch di personalizzazioni del fork (es. `agentsmaestro/git-ui`)
- I commit di personalizzazione iniziano con prefisso `[AM]` per essere identificabili nei merge

## Licenza

MIT, ereditata da Happy upstream. Vedi [LICENSE](./LICENSE).
