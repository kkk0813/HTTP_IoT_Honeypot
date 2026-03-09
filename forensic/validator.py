# ============================================================================
# forensic/validator.py — Answer Validation Engine
# ============================================================================

import shlex
import re
from .scenarios import get_scenario


def validate_step1(scenario_id, selected_line_ids):
    """Step 1: Detection — Did the student correctly flag malicious log lines?"""
    scenario = get_scenario(scenario_id)
    if not scenario:
        return {'passed': False, 'error': 'Scenario not found'}

    correct_ids = scenario['step1_answer']
    threshold = scenario['step1_threshold']
    selected = set(selected_line_ids)

    true_positives = selected & correct_ids
    false_positives = selected - correct_ids
    missed = correct_ids - selected

    score = len(true_positives)
    total = len(correct_ids)
    passed = score >= threshold

    if passed:
        if not false_positives and not missed:
            feedback = f'Perfect detection! You identified all {total} malicious entries with zero false positives.'
        elif not false_positives:
            feedback = f'Good detection — you found {score}/{total} threats with no false positives.'
        else:
            feedback = f'Passed — {score}/{total} threats found, but {len(false_positives)} false positive(s). In a real SOC, false positives waste analyst time.'
    else:
        feedback = f'Not enough threats identified. Found {score}/{total} (need {threshold}). Look for unusual User-Agents, repeated POST requests, and non-standard HTTP paths.'

    return {
        'passed': passed,
        'score': score,
        'total': total,
        'threshold': threshold,
        'correct': sorted(true_positives),
        'missed': sorted(missed),
        'false_positives': sorted(false_positives),
        'feedback': feedback,
        'explanation': scenario['explanations']['step1'] if passed else None
    }


def validate_step2(scenario_id, attack_type, botnet):
    """Step 2: Identification — Correct attack type and botnet?"""
    scenario = get_scenario(scenario_id)
    if not scenario:
        return {'passed': False, 'error': 'Scenario not found'}

    correct_type = scenario['step2_attack_type'].lower()
    correct_botnet = scenario['step2_botnet'].lower()

    type_match = correct_type in attack_type.lower() or attack_type.lower() in correct_type
    botnet_match = correct_botnet in botnet.lower() or botnet.lower() in correct_botnet

    passed = type_match and botnet_match

    if passed:
        feedback = f'Correct identification! Attack type: {scenario["step2_attack_type"]}, Botnet: {scenario["step2_botnet"]}.'
    elif type_match:
        feedback = f'Attack type is correct ({scenario["step2_attack_type"]}), but the botnet identification is wrong. Review the User-Agent strings and payload patterns.'
    elif botnet_match:
        feedback = f'Botnet identified correctly ({scenario["step2_botnet"]}), but the attack type is wrong. What is the bot primarily doing — scanning, brute forcing, injecting, or uploading?'
    else:
        feedback = 'Both incorrect. Re-examine the payload content and User-Agent strings in the malicious lines.'

    return {
        'passed': passed,
        'type_correct': type_match,
        'botnet_correct': botnet_match,
        'expected_type': scenario['step2_attack_type'],
        'expected_botnet': scenario['step2_botnet'],
        'feedback': feedback,
        'explanation': scenario['explanations']['step2'] if passed else None
    }


def validate_step3(scenario_id, command_string):
    """
    Step 3: Reconstruction — Validate the student's CLI command.
    Always returns the reference command so students can compare.
    """
    scenario = get_scenario(scenario_id)
    if not scenario:
        return {'passed': False, 'error': 'Scenario not found'}

    reference_cmd = scenario.get('step3_reference_command', '')
    command = command_string.strip()

    if not command:
        return {
            'passed': False,
            'feedback': 'No command entered. Type a CLI command that would reproduce this attack.',
            'reference_command': reference_cmd
        }

    # Safely tokenize
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    command_lower = command.lower()
    tokens_lower = [t.lower() for t in tokens]

    # Check against each valid pattern
    best_match = None
    best_score = 0

    for validation in scenario['step3_validations']:
        required = validation['required']
        found = []
        missing = []

        for keyword in required:
            kw_lower = keyword.lower()
            if kw_lower in command_lower or any(kw_lower in t for t in tokens_lower):
                found.append(keyword)
            else:
                missing.append(keyword)

        score = len(found)
        if score > best_score:
            best_score = score
            best_match = {
                'tool': validation['tool'],
                'description': validation['description'],
                'required': required,
                'found': found,
                'missing': missing,
                'total': len(required),
                'score': score
            }

    if not best_match:
        return {
            'passed': False,
            'feedback': 'Command not recognized. Start with the tool name (curl, hydra, nmap, etc.).',
            'reference_command': reference_cmd
        }

    passed = len(best_match['missing']) == 0

    if passed:
        feedback = f'Correct reconstruction using {best_match["tool"]}! All required components present: {", ".join(best_match["found"])}.'
    else:
        feedback = (
            f'Close! Detected {best_match["tool"]} command with {best_match["score"]}/{best_match["total"]} components. '
            f'Missing: {", ".join(best_match["missing"])}. '
            f'Hint: {best_match["description"]}.'
        )

    return {
        'passed': passed,
        'matched_tool': best_match['tool'],
        'found_keywords': best_match['found'],
        'missing_keywords': best_match['missing'],
        'score': best_match['score'],
        'total': best_match['total'],
        'feedback': feedback,
        'reference_command': reference_cmd,
        'explanation': scenario['explanations']['step3'] if passed else None
    }