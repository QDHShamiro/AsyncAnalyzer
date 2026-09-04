"""
Reference port of the AsyncAnalyzer.ps1 verdict logic (Get-ModFeatureVector +
Invoke-MlModel + Get-ModVerdict). Kept byte-for-byte equivalent to the
PowerShell so we can test the end-to-end behaviour here. If you change the
scoring in the .ps1, change it here too and re-run test_verdict.py.
"""

import json
import math
import os

import features
from features import FEATURE_NAMES, raw_to_vector

_MODEL = json.load(open(os.path.join(os.path.dirname(__file__), "model.json")))
_W = _MODEL["weights"]
_B = _MODEL["intercept"]
_ORDER = _MODEL["feature_order"]


def ml_probability(raw_vec):
    z = _B + sum(_W[_ORDER[i]] * raw_vec[i] for i in range(len(_ORDER)))
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def band(score):
    if score >= 85:
        return "Confirmed"
    if score >= 60:
        return "Likely"
    if score >= 30:
        return "Review"
    return "Clean"


def verdict(raw):
    """raw = the raw-signals dict (same one features.extract_from_jar returns,
    plus provenance flags). Returns {score, band, probability}."""
    vec = raw_to_vector(raw)
    p = ml_probability(vec)
    score = round(p * 100)

    if raw.get("hash_known_cheat"):
        score = 100
    if raw.get("pkgpath"):
        score = max(score, 80)
    # mechanism-based hard rules (mirror of AsyncAnalyzer.ps1 Get-ModVerdict)
    # A large entry made of one repeated byte. There is no innocent version: it is
    # padding, and padding exists to change the file's size and therefore its SHA1,
    # so a hash from someone else's copy does not match this one. Doomsday's own
    # download page offers it as a "Randomize size" checkbox. 0 hits across 179 real
    # libraries, 1 on the real loader.
    if raw.get("padding_entry", 0) > 0:
        score = max(score, 60)
    # An agent manifest is how an injected client gets into the game. It is ALSO
    # how AspectJ, ByteBuddy, OpenTelemetry, spring-instrument, H2,
    # kotlinx-coroutines and Mixin itself work - and six of those came out
    # Confirmed 90 against the negative corpus. Mixin is the framework nearly every
    # Minecraft mod is built on; a copy of it in a mods folder was an accusation.
    #
    # Measured across all seven: no loader id, no mixin config, no coremod, no cheat
    # package, no hidden payload, and every obfuscation metric exactly 0. What a
    # Minecraft injector cannot avoid is being ABOUT Minecraft, or hiding what it
    # is. So the accusing floor needs one corroborating fact; without one the jar
    # is a Java library in the wrong folder - worth a look, not a verdict.
    if raw.get("java_agent"):
        bc = raw.get("bytecode") or {}
        MC_BC = ("bc_movepacket", "bc_rotation", "bc_attack", "bc_blockplace",
                 "bc_blockbreak", "bc_container", "bc_motion", "bc_pktlisten",
                 "bc_entityscan", "bc_render", "bc_input", "bc_mixintarget",
                 "bc_coretarget")
        agent_corroborated = (
            # it says it is a Minecraft mod, or is built as one
            bool(raw.get("loader_ids"))
            or raw.get("legit_modid")
            or raw.get("mixin_configs", 0) > 0
            or raw.get("core_mod")
            or bool(bc.get("mixin_areas"))
            or any(bc.get(k + "_ratio", 0) or bc.get(k, 0) for k in MC_BC)
            # or it is hiding what it is
            or raw.get("pkgpath")
            or raw.get("filename_client")
            or raw.get("cheatsite")
            or raw.get("hidden_payload", 0) > 0
            or raw.get("padding_entry", 0) > 0
            or raw.get("fake_identity")
            or raw.get("random_name")
            or raw.get("singlechar_cls_pct", 0) > 0.15
            or raw.get("novowel_cls_pct", 0) > 0.15
            or raw.get("numeric_cls_pct", 0) > 0.15
            or raw.get("fullwidth_cls_pct", 0) > 0
            or raw.get("japanese_cls_pct", 0) > 0
            or raw.get("high_entropy_pct", 0) > 0.20
        )
        if agent_corroborated:
            score = max(score, 90 if raw.get("agent_retransform") else 80)
        else:
            # Review, not Clean: mods are not Java agents, and a moderator should
            # see it. It just is not proof on its own.
            score = max(score, 35)
    if raw.get("hidden_payload", 0) > 0:
        score = max(score, 75)
    if len(raw.get("loader_ids", []) or []) >= 3:
        score = max(score, 70)
    if raw.get("cheatsite"):
        score = max(score, 75)
    if raw.get("fake_identity"):
        score = max(score, 70)
    if raw.get("filename_client"):
        score = max(score, 60)

    # Behaviour read out of the bytecode (see ml/bytecode.py). Survives string
    # encryption, because calling a Minecraft method means naming it in the pool.
    bc = raw.get("bytecode") or {}
    # Set when a behaviour is recognised for certain but its legality is a server
    # rule rather than a technical fact. It renames the band; it never raises it.
    policy = False
    if bc.get("classes_parsed", 0) > 0:
        # aim/killaura: forging your own movement packet with a computed rotation,
        # in the SAME class. Both present but never together = a large jar with
        # unrelated movement and camera code, not one module - Review only. This
        # is the exact rule that scored a real utility client (Feather) Likely 60.
        if bc.get("bc_aimcheat_ratio", 0) > 0:
            score = max(score, 85)
        elif bc.get("bc_movepacket_ratio", 0) > 0 and bc.get("bc_rotation_ratio", 0) > 0:
            score = max(score, 35)
        # dropper: decrypt, then define a class from the plaintext
        if bc.get("bc_crypto_ratio", 0) >= 0.5 and (
                bc.get("bc_classload_ratio", 0) > 0 or bc.get("bc_reflect_ratio", 0) >= 0.5):
            score = max(score, 85)
        # Forging movement paired with a second thing no legitimate mod combines it
        # with, in the same class. Measured at 0 hits across 405 clean jars, 177 of
        # them real libraries.
        if bc.get("bc_scaffold_ratio", 0) > 0:
            score = max(score, 85)          # scaffold / tower
        elif bc.get("bc_blockplace_ratio", 0) > 0 and bc.get("bc_movepacket_ratio", 0) > 0:
            score = max(score, 35)
        if bc.get("bc_speedmotion_ratio", 0) > 0:
            score = max(score, 85)          # speed / no-fall / blink
        elif bc.get("bc_movepacket_ratio", 0) > 0 and bc.get("bc_motion_ratio", 0) > 0:
            score = max(score, 35)
        if bc.get("bc_containermove_ratio", 0) > 0:
            score = max(score, 85)          # inventory-move
        elif bc.get("bc_container_ratio", 0) > 0 and bc.get("bc_movepacket_ratio", 0) > 0:
            score = max(score, 35)
        if bc.get("bc_instrument_ratio", 0) > 0:
            score = max(score, 80)
        # Strong, but not the same order of certainty -> flag, do not confirm.
        if bc.get("bc_movepacket_ratio", 0) > 0 and bc.get("bc_input_ratio", 0) == 0:
            score = max(score, 60)          # movement not coming from the player
        if bc.get("bc_killaura_ratio", 0) > 0:
            score = max(score, 60)          # killaura / reach / triggerbot targeting
        elif bc.get("bc_entityscan_ratio", 0) > 0 and bc.get("bc_attack_ratio", 0) > 0:
            score = max(score, 35)
        if bc.get("bc_attack_ratio", 0) > 0 and bc.get("bc_input_ratio", 0) == 0:
            score = max(score, 60)          # autoclicker / triggerbot
        # The other half of the real false positive: pktlisten and motion both
        # present, spread across different classes ("[pktlisten in aX.class,
        # bB.class; motion in bI.class, bW.class]" in the report that triggered
        # this). Never Likely on a jar-wide count alone.
        if bc.get("bc_antikb_ratio", 0) > 0:
            score = max(score, 60)          # velocity / anti-knockback
        elif bc.get("bc_pktlisten_ratio", 0) > 0 and bc.get("bc_motion_ratio", 0) > 0:
            score = max(score, 35)
        if bc.get("bc_blockbreak_ratio", 0) > 0 and bc.get("bc_input_ratio", 0) == 0:
            score = max(score, 60)          # nuker
        if bc.get("bc_freecam_ratio", 0) > 0 and bc.get("bc_movepacket_ratio", 0) == 0:
            score = max(score, 60)          # freecam
        elif (bc.get("bc_rotation_ratio", 0) > 0 and bc.get("bc_render_ratio", 0) > 0
                and bc.get("bc_movepacket_ratio", 0) == 0):
            score = max(score, 35)
        # A mod that finds its OWN jar and deletes it. Measured: 0 of 179 real
        # libraries, caught on cheat/SelfWipe.java, and NOT caught on
        # clean/NativeUnpack.java - the library that unpacks a native to temp
        # and cleans up, which is the only shape that shares the two halves.
        # Likely rather than Confirmed: an earlier form of this rule hit a real
        # library in CI twice, and that cannot be reproduced here to rule out.
        if bc.get("bc_selfwipe_ratio", 0) > 0:
            score = max(score, 60)
        # Recognised for certain; legality is a server rule, not a technical fact.
        # These are scored into Review and the band is renamed, never raised.
        if (bc.get("bc_render_ratio", 0) > 0 and bc.get("bc_entityscan_ratio", 0) > 0
                and not (raw.get("verified") or raw.get("legit_modid"))):
            score = max(score, 35)
            policy = True                   # ESP or a mob-radar minimap
        if (bc.get("bc_blockplace_ratio", 0) > 0 and bc.get("bc_input_ratio", 0) > 0
                and bc.get("bc_movepacket_ratio", 0) == 0
                and not (raw.get("verified") or raw.get("legit_modid"))):
            score = max(score, 35)
            policy = True                   # schematic printer

        # Behaviour beats text: a jar that only goes through the game's own systems
        # and forges nothing cannot cheat, whatever its names and strings look like.
        forges = any(bc.get(k, 0) > 0 for k in (
            "bc_movepacket_ratio", "bc_rotation_ratio", "bc_motion_ratio", "bc_attack_ratio",
            "bc_classload_ratio", "bc_instrument_ratio", "bc_unsafe_ratio", "bc_exec_ratio",
            "bc_crypto_ratio", "bc_net_ratio"))
        uses_game_only = any(bc.get(k, 0) > 0 for k in
                             ("bc_input_ratio", "bc_container_ratio", "bc_render_ratio"))
        # filename_client belongs in this list and was missing from it. The cap is
        # behaviour beating a TEXT heuristic; a filename matching a known cheat
        # client is identity, the same kind of thing as a hash or a package path.
        if (not policy and not forges and uses_game_only
                and not raw.get("hash_known_cheat") and not raw.get("pkgpath")
                and not raw.get("cheatsite") and not raw.get("filename_client")):
            score = min(score, 20)

    # Random / hash-style filename on an unverified mod: floor to Review (never a flag)
    # so it is surfaced instead of slipping through as "unknown". Verified / legit mods
    # are exempt (capped safe below). Mirrors Get-ModVerdict in AsyncAnalyzer.ps1.
    if raw.get("random_name") and not (raw.get("verified") or raw.get("legit_modid")):
        floor = 35
        if (
            raw.get("high_entropy_pct", 0.0) >= 0.25
            or raw.get("singlechar_cls_pct", 0.0) >= 0.25
            or raw.get("fullwidth_cls_pct", 0.0) > 0
            or raw.get("nested_hollow")
            or (
                raw.get("reflection_count", 0) >= 2
                and (raw.get("http_download") or raw.get("runtime_exec") or raw.get("http_exfil"))
            )
        ):
            floor = 55
        if score < floor:
            score = floor

    # Mirror of the PS cap: a hash-verified file IS that mod (cap stays), but a
    # SELF-DECLARED mod id only protects a jar carrying no hard evidence. Claiming
    # to be a known mod while carrying injector/cheat evidence is impersonation.
    hard_evidence = (
        raw.get("hash_known_cheat")
        or raw.get("pkgpath")
        or raw.get("java_agent")
        or raw.get("hidden_payload", 0) > 0
        or len(raw.get("loader_ids", []) or []) >= 3
        or raw.get("cheatsite")
        or raw.get("fake_identity")
    )
    if raw.get("verified"):
        score = min(score, 20)
    elif raw.get("legit_modid"):
        if hard_evidence:
            score = max(score, 85)
        else:
            score = min(score, 20)

    b = band(score)
    # Only renamed while it sits in Review. If anything else pushed the same jar to
    # Likely or Confirmed, that finding stands - a printer that also forges movement
    # packets is not a printer.
    if policy and b == "Review":
        b = "ServerRule"
    return {"score": score, "band": b, "probability": round(p * 100), "policy": policy}


if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        r = features.extract_from_jar(path)
        print(path, verdict(r))
