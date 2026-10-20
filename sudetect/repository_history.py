"""Bounded observed commit snapshots and patches; no fabricated revisions."""
import json
import re
from urllib.parse import parse_qs, quote, unquote, urlsplit
from .repository_assets import tree_url
from .github_history import analyze_repository_patch


def history_url(candidate):
    tree = tree_url(candidate)
    if not tree:
        return None
    parts = urlsplit(tree).path.split('/')
    return ('https://api.github.com/repos/' + parts[2] + '/' + parts[3] +
            '/commits?sha=' + quote(unquote(parts[-1]), safe='') + '&per_page=5')


def analyze_history(body, url):
    """Return value-free coverage and exact locators for observed revisions."""
    report = {'document_type': 'repository_history', 'content': 'NOT_INSPECTED',
              'analysis_complete': False, 'commits_examined': 0,
              'pending_reviews': ['history_window_not_exhaustive']}
    refs = []
    try:
        parts = urlsplit(url)
        match = re.fullmatch(r'/repos/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commits', parts.path)
        query = parse_qs(parts.query)
        if (parts.scheme != 'https' or parts.netloc != 'api.github.com' or parts.fragment
                or not match or set(query) != {'sha', 'per_page'} or query['per_page'] != ['5']
                or len(query['sha']) != 1 or len(body) > 2_097_152):
            raise ValueError
        slug = match.group(1) + '/' + match.group(2)
        if not tree_url({'slug': slug, 'source_revision': {'kind': 'branch_mutable', 'value': query['sha'][0]}}):
            raise ValueError
        rows = json.loads(body)
        if not isinstance(rows, list) or len(rows) > 5:
            raise ValueError
        shas = [row.get('sha') if isinstance(row, dict) else None for row in rows]
        if (any(not isinstance(sha, str) or not re.fullmatch('[a-fA-F0-9]{40}', sha) for sha in shas)
                or len(set(shas)) != len(shas)):
            raise ValueError
        for sha in dict.fromkeys(shas):
            refs.append(('repository_snapshot', tree_url({'slug': slug,
                'source_revision': {'kind': 'commit', 'value': sha}})))
            refs.append(('repository_patch', f'https://github.com/{slug}/commit/{sha}.patch'))
        report.update(analysis_complete=True, commits_examined=len(shas),
                      snapshots_emitted=len(shas), patches_emitted=len(shas))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        report['pending_reviews'].append('history_metadata_incomplete')
    return report, refs
