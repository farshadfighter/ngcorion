"""PDF reports may load only the bundled fonts and data: URLs (the logo);
WeasyPrint is never allowed to reach the network or another local file."""
import pytest

from app.modules.reports.render import FONTS, _fetcher


def test_bundled_font_and_data_url_load():
    f = _fetcher()
    assert f.fetch((FONTS / "DejaVuSansMono.ttf").as_uri())
    assert f.fetch("data:image/png;base64,iVBORw0KGgo=")


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
    "https://example.com/x.png",
    "ftp://example.com/x",
])
def test_other_resources_are_blocked(url):
    with pytest.raises(ValueError):
        _fetcher().fetch(url)


def test_path_escape_from_the_font_directory_is_blocked():
    with pytest.raises(ValueError):
        _fetcher().fetch((FONTS / ".." / "render.py").as_uri())
