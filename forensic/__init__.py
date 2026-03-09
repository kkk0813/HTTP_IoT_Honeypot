# ============================================================================
# forensic/__init__.py — Forensic Reconstructor Blueprint
# ============================================================================
# Blue Team SOC analyst training module.
# Routes: landing page, scenario loader, validation API endpoints.
# ============================================================================

from flask import Blueprint, render_template, request, jsonify
from .scenarios import get_scenario, get_all_scenarios
from .validator import validate_step1, validate_step2, validate_step3

forensic_bp = Blueprint('forensic', __name__)


# ============================================================================
# PAGE ROUTES
# ============================================================================

@forensic_bp.route('/forensic')
def forensic_landing():
    """Scenario picker — shows all available investigation cases."""
    scenarios = get_all_scenarios()
    return render_template('forensic/landing.html',
                           active_page='forensic',
                           scenarios=scenarios)


@forensic_bp.route('/forensic/<scenario_id>')
def forensic_lab(scenario_id):
    """Load a specific forensic investigation scenario."""
    scenario = get_scenario(scenario_id)
    if not scenario:
        return render_template('forensic/landing.html',
                               active_page='forensic',
                               scenarios=get_all_scenarios(),
                               error='Scenario not found.')

    # Build safe data for the frontend (don't expose answers)
    scenario_data = {
        'id': scenario['id'],
        'title': scenario['title'],
        'difficulty': scenario['difficulty'],
        'difficulty_color': scenario['difficulty_color'],
        'icon': scenario['icon'],
        'attack_type': scenario['attack_type'],
        'botnet': scenario['botnet'],
        'mitre_id': scenario['mitre_id'],
        'summary': scenario['summary'],
        'learning_objectives': scenario['learning_objectives'],
        'logs': [
            {'id': log['id'], 'raw': log['raw']}
            for log in scenario['logs']
        ],
        'total_logs': len(scenario['logs']),
        'malicious_count': len(scenario['step1_answer']),
    }

    return render_template('forensic/lab.html',
                           active_page='forensic',
                           scenario=scenario_data)


# ============================================================================
# VALIDATION API ENDPOINTS
# ============================================================================

@forensic_bp.route('/api/forensic/validate_step1', methods=['POST'])
def api_validate_step1():
    """Validate Step 1: which log lines did the student flag as malicious?"""
    data = request.json
    scenario_id = data.get('scenario_id', '')
    selected = data.get('selected_lines', [])

    result = validate_step1(scenario_id, selected)
    return jsonify(result)


@forensic_bp.route('/api/forensic/validate_step2', methods=['POST'])
def api_validate_step2():
    """Validate Step 2: attack type and botnet identification."""
    data = request.json
    scenario_id = data.get('scenario_id', '')
    attack_type = data.get('attack_type', '')
    botnet = data.get('botnet', '')

    result = validate_step2(scenario_id, attack_type, botnet)
    return jsonify(result)


@forensic_bp.route('/api/forensic/validate_step3', methods=['POST'])
def api_validate_step3():
    """Validate Step 3: reconstructed CLI command."""
    data = request.json
    scenario_id = data.get('scenario_id', '')
    command = data.get('command', '')

    result = validate_step3(scenario_id, command)
    return jsonify(result)


@forensic_bp.route('/api/forensic/hint', methods=['POST'])
def api_get_hint():
    """Provide a contextual hint for the current step."""
    data = request.json
    scenario_id = data.get('scenario_id', '')
    step = data.get('step', 1)

    scenario = get_scenario(scenario_id)
    if not scenario:
        return jsonify({'hint': 'Scenario not found.'})

    hints = {
        1: [
            'Look at the HTTP method — normal browsing is mostly GET, attacks often use POST.',
            'Check the User-Agent strings — bots often have empty, unusual, or tool-specific agents.',
            'Compare response status codes — 401 (Unauthorized) after POST usually means failed login attempts.',
            f'There are {len(scenario["step1_answer"])} malicious lines hidden among {len(scenario["logs"])} total entries.'
        ],
        2: [
            f'The malicious requests target the path: look at what endpoints are being hit.',
            'The User-Agent string is a key indicator — many botnets have distinctive signatures.',
            'Think about what the payload is trying to achieve: login? execute commands? upload files?',
        ],
        3: [
            'Start with the tool name: curl, hydra, nmap, sqlmap, or gobuster.',
            'Include the target IP, the HTTP method, and the attack path.',
            f'The attack type is {scenario["attack_type"]} — which tool is commonly used for this?',
        ]
    }

    step_hints = hints.get(step, hints[1])
    # Return a different hint each time based on request count
    hint_index = data.get('hint_count', 0) % len(step_hints)
    return jsonify({'hint': step_hints[hint_index]})


@forensic_bp.route('/api/forensic/log_detail', methods=['POST'])
def api_log_detail():
    """Get detailed breakdown of a specific log line (after Step 1 is passed)."""
    data = request.json
    scenario_id = data.get('scenario_id', '')
    line_id = data.get('line_id', -1)

    scenario = get_scenario(scenario_id)
    if not scenario:
        return jsonify({'error': 'Scenario not found'})

    log = next((l for l in scenario['logs'] if l['id'] == line_id), None)
    if not log:
        return jsonify({'error': 'Log line not found'})

    return jsonify({
        'id': log['id'],
        'malicious': log['malicious'],
        'payload': log.get('payload', ''),
        'tool_hint': log.get('tool_hint', ''),
    })