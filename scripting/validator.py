# ============================================================================
# scripting/validator.py — Code Structure Validation Engine
# ============================================================================
# Validates student code structurally — checks for required keywords,
# constructs, and patterns without ever executing the code.
# Uses Python's re module for pattern matching.
# ============================================================================

import re
from .lessons import get_lesson


def validate_code(lesson_id, code):
    """
    Validate student code against the lesson's required constructs.
    Returns pass/fail, matched/missing keywords, and reference solution.
    """
    lesson = get_lesson(lesson_id)
    if not lesson:
        return {'passed': False, 'error': 'Lesson not found'}

    code = code.strip()
    if not code:
        return {
            'passed': False,
            'feedback': 'No code submitted. Write your script in the editor above.',
            'reference_code': lesson['reference_code'],
            'reference_explanation': lesson['reference_explanation']
        }

    # Strip comment lines — prevents starter code hints from matching keywords.
    # Comments use # in both Bash and Python.
    code_lines = code.split('\n')
    active_lines = [line for line in code_lines if not line.strip().startswith('#')]
    active_code = '\n'.join(active_lines).lower()

    # Also reject if only starter code remains (no student additions)
    starter = lesson.get('starter_code', '').strip()
    starter_lines = [line for line in starter.split('\n') if not line.strip().startswith('#')]
    starter_active = '\n'.join(starter_lines).strip().lower()
    if active_code.strip() == starter_active or not active_code.strip():
        return {
            'passed': False,
            'feedback': 'No code added yet. The editor still contains only the starter template — write your solution below it.',
            'reference_code': lesson['reference_code'],
            'reference_explanation': lesson['reference_explanation']
        }

    found = []
    missing = []

    for rule in lesson['validations']:
        keyword = rule['keyword'].lower()
        if keyword in active_code:
            found.append({
                'keyword': rule['keyword'],
                'label': rule['label'],
                'matched': True
            })
        else:
            missing.append({
                'keyword': rule['keyword'],
                'label': rule['label'],
                'description': rule['description'],
                'matched': False
            })

    total = len(lesson['validations'])
    score = len(found)
    passed = len(missing) == 0

    if passed:
        feedback = f'All {total} required constructs found! Your script has the right structure.'
    elif score >= total - 1:
        feedback = f'Almost there — {score}/{total} constructs found. Missing: {missing[0]["label"]}. {missing[0]["description"]}.'
    elif score > 0:
        missing_labels = ", ".join(m['label'] for m in missing)
        feedback = f'{score}/{total} constructs found. Missing: {missing_labels}.'
    else:
        feedback = 'No required constructs detected. Read the challenge description and hints carefully.'

    return {
        'passed': passed,
        'score': score,
        'total': total,
        'found': found,
        'missing': missing,
        'feedback': feedback,
        'reference_code': lesson['reference_code'],
        'reference_explanation': lesson['reference_explanation']
    }