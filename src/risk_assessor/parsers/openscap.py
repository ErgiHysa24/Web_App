"""Parser for OpenSCAP XCCDF results.

OpenSCAP produce un file XML (XCCDF) con namespace tipo:
  http://checklists.nist.gov/xccdf/1.2

Ogni <rule-result> contiene:
  <idref>  -> ID della regola
  <result> -> pass | fail | notapplicable | error | unknown | fixed

Per ogni "fail" viene generato un Finding. Le severity sono nel Benchmark
(ogni <Rule> ha <severity>), ma per semplicità inferiamo severity dal
result + id della regola (contiene di solito "high"/"medium"/"low").
"""
from __future__ import annotations
import re
# stdlib ET solo per i tipi (Element); il parsing passa da defusedxml (SafeET)
import xml.etree.ElementTree as ET  # nosec B405

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from risk_assessor.models import Finding, Severity, Confidence


# Namespace XCCDF
XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"
NS = {"x": XCCDF_NS}

# Severity nei nomi/ID delle regole
_SEVERITY_HINTS = [
    (re.compile(r"high|important|critical", re.IGNORECASE), Severity.HIGH),
    (re.compile(r"medium|moderate", re.IGNORECASE), Severity.MEDIUM),
    (re.compile(r"low|minor", re.IGNORECASE), Severity.LOW),
]


def parse_openscap(xml_text: str) -> list[Finding]:
    if xml_text.startswith("__NO_DATASTREAM__"):
        system = xml_text[len("__NO_DATASTREAM__"):].strip() or "questo sistema"
        return [Finding(
            title="OpenSCAP: contenuto SCAP non disponibile per questo sistema",
            category="compliance",
            severity=Severity.INFO,
            description=(
                f"OpenSCAP è installato ma non c'è un datastream SCAP Security Guide (SSG) "
                f"per {system}. Le regole CIS/STIG non sono state valutate: questo "
                "controllo non dice nulla sulla conformità del sistema."
            ),
            evidence=f"Nessun datastream adatto a {system} in /usr/share/xml/scap/ssg/content/",
            recommendation=(
                "Scaricare il datastream per questa distribuzione e versione dalle release "
                "di ComplianceAsCode (https://github.com/ComplianceAsCode/content/releases) "
                "e copiarlo in /usr/share/xml/scap/ssg/content/."
            ),
            source="openscap:no-datastream",
            confidence=Confidence.HIGH,
        )]

    if not xml_text or not xml_text.strip():
        return [Finding(
            title="OpenSCAP: valutazione non completata",
            category="compliance",
            severity=Severity.INFO,
            description=("OpenSCAP non ha prodotto risultati: l'assenza di regole fallite NON "
                         "significa conformità."),
            evidence="",
            recommendation="Verificare che oscap sia installato e il datastream disponibile.",
            source="openscap:failed",
            confidence=Confidence.LOW,
        )]

    # Prova prima con namespace, poi senza
    root = None
    try:
        root = SafeET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException) as e:
        return [Finding(
            title="OpenSCAP: output non valido",
            category="compliance",
            severity=Severity.INFO,
            description=("Il risultato di OpenSCAP non è leggibile: la conformità non è stata "
                         "verificata."),
            evidence=f"{type(e).__name__}: {e} | inizio: {xml_text[:150]} | fine: {xml_text[-150:]}",
            recommendation="Verificare la versione di OpenSCAP.",
            source="openscap:failed",
            confidence=Confidence.LOW,
        )]

    # Trova tutte le rule-result (con o senza namespace)
    rule_results = _findall_any_ns(root, "rule-result")
    if not rule_results:
        # prova "rule-result" senza namespace (fallback)
        rule_results = list(root.iter("rule-result"))

    # Raccogli fail e pass
    fails: list[tuple[str, str]] = []  # (rule_id, severity)
    total = 0
    pass_count = 0
    not_applicable = 0
    other = 0  # error, unknown, notchecked, ...
    errors = 0  # error, unknown: la regola doveva essere verificata ma il controllo non è riuscito

    for rr in rule_results:
        # idref è un ATTRIBUTO di <rule-result>, non un figlio
        idref = rr.get("idref") or ""
        if not idref:
            # fallback: cerca come figlio (alcuni tool lo mettono come child)
            idref = _findtext_any_ns(rr, "idref") or ""

        # severity è un attributo opzionale di <rule-result>
        severity_attr = (rr.get("severity") or "").strip().lower()

        result = (_findtext_any_ns(rr, "result") or "").strip().lower()
        if not result or result == "notselected":
            # le regole non selezionate dal profilo non sono state valutate
            continue
        total += 1
        if result == "fail":
            if severity_attr in ("high", "medium", "low", "unknown"):
                severity = _attr_to_severity(severity_attr)
            else:
                severity = _infer_severity(idref)
            fails.append((idref, severity.value))
        elif result == "pass":
            pass_count += 1
        elif result == "notapplicable":
            not_applicable += 1
        else:
            other += 1
            if result in ("error", "unknown"):
                errors += 1

    findings: list[Finding] = []

    # Un finding per ogni fail
    for rule_id, sev_value in fails:
        sev = Severity(sev_value)
        findings.append(Finding(
            title=f"OpenSCAP fail: {rule_id[:80]}",
            category="compliance",
            severity=sev,
            description=f"Regola di compliance non superata: {rule_id}",
            evidence=f"rule: {rule_id}\nresult: fail",
            recommendation="Verificare la configurazione e applicare la regola.",
            source="openscap:fail",
            confidence=Confidence.HIGH,
        ))

    # Regole che dovevano essere verificate ma il cui controllo è fallito: non sono conformità.
    if errors:
        findings.append(Finding(
            title=f"OpenSCAP: {errors} regole non verificate (errore)",
            category="compliance",
            severity=Severity.INFO,
            description=(f"Per {errors} regole su {total} il controllo di OpenSCAP è finito con un errore: "
                         "quelle regole non sono state verificate e non contano come superate."),
            evidence=f"error/unknown={errors}, passed={pass_count}, failed={len(fails)}",
            recommendation="Eseguire oscap a mano con --verbose per vedere gli errori (spesso mancano privilegi).",
            source="openscap:partial",
            confidence=Confidence.LOW,
        ))

    # Summary
    if fails:
        findings.append(Finding(
            title=f"OpenSCAP: {len(fails)} regole non superate su {total}",
            category="compliance",
            severity=Severity.INFO,
            description=(
                f"OpenSCAP ha valutato {total} regole: "
                f"{len(fails)} fail, {pass_count} pass, {not_applicable} n/a."
            ),
            evidence=f"failed={len(fails)}, passed={pass_count}, not_applicable={not_applicable}",
            recommendation="Revisionare le regole non superate e pianificare le correzioni.",
            source="openscap:summary",
            confidence=Confidence.HIGH,
        ))
    elif errors > pass_count:
        findings.append(Finding(
            title="OpenSCAP: controllo non completato",
            category="compliance",
            severity=Severity.INFO,
            description=(f"Più regole in errore ({errors}) che superate ({pass_count}): la conformità NON è "
                         "stata verificata."),
            evidence=f"passed={pass_count}, error/unknown={errors}, not_applicable={not_applicable}",
            recommendation="Eseguire oscap a mano con --verbose per vedere gli errori.",
            source="openscap:failed",
            confidence=Confidence.LOW,
        ))
    elif pass_count == 0:
        # Nessuna regola superata né fallita: il contenuto non riguarda questo
        # sistema (per esempio un datastream di un'altra versione) o il controllo
        # non è riuscito. Non è un "tutto ok".
        findings.append(Finding(
            title="OpenSCAP: nessuna regola applicabile a questo sistema",
            category="compliance",
            severity=Severity.INFO,
            description=(
                f"Delle {total} regole del profilo nessuna è stata superata o fallita "
                f"({not_applicable} non applicabili, {other} con errore o non verificabili). "
                "Il contenuto SCAP probabilmente non corrisponde a questa distribuzione o "
                "versione: la conformità NON è stata verificata."
            ),
            evidence=f"passed=0, failed=0, not_applicable={not_applicable}, other={other}",
            recommendation=(
                "Usare il datastream SSG della distribuzione e versione esatte del sistema "
                "(https://github.com/ComplianceAsCode/content/releases)."
            ),
            source="openscap:not-applicable",
            confidence=Confidence.HIGH,
        ))
    else:
        findings.append(Finding(
            title="OpenSCAP: nessuna regola non superata",
            category="compliance",
            severity=Severity.INFO,
            description=(f"Nessuna delle {total} regole valutate è fallita"
                         + (f"; {errors} non sono state verificate per un errore." if errors else ".")),
            evidence=f"passed={pass_count}, not_applicable={not_applicable}, other={other}, errors={errors}",
            recommendation=("Controllare le regole in errore." if errors else "Nessuna azione richiesta."),
            source="openscap:summary",
            confidence=Confidence.MEDIUM if errors else Confidence.HIGH,
        ))

    return findings


def _findall_any_ns(root: ET.Element, tag: str) -> list[ET.Element]:
    """Trova elementi ignorando il namespace."""
    return [el for el in root.iter() if el.tag.endswith("}" + tag) or el.tag == tag]


def _findtext_any_ns(parent: ET.Element, tag: str) -> str | None:
    for child in parent:
        if child.tag.endswith("}" + tag) or child.tag == tag:
            return child.text or ""
    return None


_ATTR_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _attr_to_severity(value: str) -> Severity:
    """Severità dall'attributo `severity` di <rule-result> (high/medium/low/unknown)."""
    return _ATTR_SEVERITY.get(value, Severity.MEDIUM)


def _infer_severity(rule_id: str) -> Severity:
    """Inferisce severity dal nome della regola (euristica)."""
    for pattern, sev in _SEVERITY_HINTS:
        if pattern.search(rule_id):
            return sev
    return Severity.MEDIUM
