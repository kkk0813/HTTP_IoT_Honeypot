# ============================================================================
# scripting/__init__.py — Code & Catch Blueprint
# ============================================================================
# Scripting training module — teaches students to write Python and Bash
# scripts for security automation.
# ============================================================================

from flask import Blueprint, render_template, request, jsonify
from .lessons import get_lesson, get_all_lessons
from .validator import validate_code

scripting_bp = Blueprint('scripting', __name__)


# ============================================================================
# PAGE ROUTES
# ============================================================================

@scripting_bp.route('/scripting')
def scripting_landing():
    """Lesson picker page."""
    lessons = get_all_lessons()
    return render_template('scripting/landing.html',
                           active_page='simulation',
                           lessons=lessons)


@scripting_bp.route('/scripting/<lesson_id>')
def scripting_editor(lesson_id):
    """Load a specific scripting lesson editor."""
    lesson = get_lesson(lesson_id)
    if not lesson:
        return render_template('scripting/landing.html',
                               active_page='simulation',
                               lessons=get_all_lessons(),
                               error='Lesson not found.')

    # Build safe data for frontend (don't expose validation keywords or reference)
    lesson_data = {
        'id': lesson['id'],
        'title': lesson['title'],
        'subtitle': lesson['subtitle'],
        'difficulty': lesson['difficulty'],
        'difficulty_color': lesson['difficulty_color'],
        'icon': lesson['icon'],
        'language': lesson['language'],
        'badge': lesson['badge'],
        'badge_color': lesson['badge_color'],
        'summary': lesson['summary'],
        'learning_objectives': lesson['learning_objectives'],
        'challenge': lesson['challenge'],
        'starter_code': lesson['starter_code'],
        'sample_log': lesson.get('sample_log'),
        'total_checks': len(lesson['validations']),
    }

    return render_template('scripting/editor.html',
                           active_page='simulation',
                           lesson=lesson_data)


# ============================================================================
# VALIDATION API
# ============================================================================

@scripting_bp.route('/api/scripting/validate', methods=['POST'])
def api_validate():
    """Validate student's code structure."""
    data = request.json
    lesson_id = data.get('lesson_id', '')
    code = data.get('code', '')

    result = validate_code(lesson_id, code)
    return jsonify(result)


@scripting_bp.route('/api/scripting/hint', methods=['POST'])
def api_hint():
    """Return a progressive hint for the current lesson."""
    data = request.json
    lesson_id = data.get('lesson_id', '')
    hint_index = data.get('hint_index', 0)

    lesson = get_lesson(lesson_id)
    if not lesson:
        return jsonify({'hint': 'Lesson not found.'})

    hints = lesson.get('hints', [])
    if not hints:
        return jsonify({'hint': 'No hints available for this lesson.'})

    # Loop hints using modulo — same pattern as forensic module
    actual_index = hint_index % len(hints)

    return jsonify({
        'hint': hints[actual_index],
        'current': actual_index + 1,
        'total': len(hints)
    })


@scripting_bp.route('/api/scripting/answer', methods=['POST'])
def api_show_answer():
    """Return the reference solution and explanation."""
    data = request.json
    lesson_id = data.get('lesson_id', '')

    lesson = get_lesson(lesson_id)
    if not lesson:
        return jsonify({'error': 'Lesson not found.'})

    return jsonify({
        'reference_code': lesson['reference_code'],
        'reference_explanation': lesson['reference_explanation']
    })