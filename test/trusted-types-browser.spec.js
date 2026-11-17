/* Playwright test: Trusted Types attribute signing under real enforcement.
 *
 * The jsdom sibling (test/trusted-types-attributes.js) uses a sink simulator
 * because jsdom has no Trusted Types. This file re-runs the same contract
 * against a real engine: /test/browser/trusted-types.html is served with
 *
 *   Content-Security-Policy: require-trusted-types-for 'script';
 *                            trusted-types dompurify tt-browser-suite tt-fixture
 *
 * so every HTML sink in the page enforces, and DOMPurify's own `dompurify`
 * policy is allowed alongside the two fixture policies used here.
 *
 * Engines without Trusted Types (Firefox, WebKit) cannot express the
 * precondition; those tests skip rather than pass vacuously.
 *
 * Each test states whether the expected outcome is a *safe rejection* (the
 * sink refuses the write / DOMPurify removes the attribute / nothing unsigned
 * is returned) or *compatible behaviour* (the sanitized string is as expected
 * because the write was properly branded).
 *
 * Note: the page code below avoids `eval`/`new Function` - under
 * `require-trusted-types-for 'script'` those are TrustedScript sinks too.
 */

'use strict';

const { test, expect } = require('@playwright/test');

const PAGE = '/test/browser/trusted-types.html';

/* Records every attribute write with the brand the engine requires for that
 * sink and whether the written value satisfies it. Read-only with respect to
 * the DOM, so it cannot itself trip the CSP. */
async function installAudit(page) {
  await page.addInitScript(() => {
    const audit = {
      writes: [],
      reset() {
        this.writes.length = 0;
        while (window.DOMPurify.removed.length > 0) {
          window.DOMPurify.removed.pop();
        }
      },
      removed() {
        return window.DOMPurify.removed.map(
          (entry) => (entry.attribute && entry.attribute.name) || null
        );
      },
      /* One fixture policy per document; policy names are unique. */
      fixture() {
        if (!window.__ttFixture) {
          window.__ttFixture = window.trustedTypes.createPolicy('tt-fixture', {
            createHTML: (input) => input,
            createScriptURL: (input) => input,
          });
        }

        return window.__ttFixture;
      },
    };

    const brandMatches = (type, value) => {
      if (type === 'TrustedHTML') return window.trustedTypes.isHTML(value);
      if (type === 'TrustedScriptURL') {
        return window.trustedTypes.isScriptURL(value);
      }

      return true;
    };

    const elementPrototype = Element.prototype;
    const originalSetAttribute = elementPrototype.setAttribute;
    const originalSetAttributeNS = elementPrototype.setAttributeNS;

    elementPrototype.setAttribute = function (name, value) {
      const tag = this.nodeName.toLowerCase();
      const attr = String(name).toLowerCase();
      let expected = null;
      try {
        expected = window.trustedTypes.getAttributeType(tag, attr);
      } catch (_) {
        expected = null;
      }

      audit.writes.push({
        sink: 'setAttribute',
        tag,
        attr,
        expected,
        signed: expected ? brandMatches(expected, value) : null,
        value: String(value),
      });

      return originalSetAttribute.call(this, name, value);
    };

    elementPrototype.setAttributeNS = function (namespaceURI, name, value) {
      const tag = this.nodeName.toLowerCase();
      const attr = String(name).split(':').pop().toLowerCase();
      let expected = null;
      try {
        expected = window.trustedTypes.getAttributeType(
          tag,
          attr,
          undefined,
          namespaceURI
        );
      } catch (_) {
        expected = null;
      }

      audit.writes.push({
        sink: 'setAttributeNS',
        tag,
        attr,
        expected,
        signed: expected ? brandMatches(expected, value) : null,
        value: String(value),
      });

      return originalSetAttributeNS.call(this, namespaceURI, name, value);
    };

    window.__ttAudit = audit;
  });
}

/* Loads the harness page. The page's own <script src> is exempt from
 * `require-trusted-types-for`, so dist/purify.js loads normally.
 *
 * Returns whether enforcement is available. A missing DOMPurify global is a
 * hard failure, not a skip: the build would be broken, not the engine. */
async function openHarness(page) {
  await installAudit(page);
  await page.goto(PAGE);
  const probe = await page.evaluate(() => ({
    hasTrustedTypes:
      Boolean(window.trustedTypes) &&
      typeof window.trustedTypes.createPolicy === 'function',
    hasDOMPurify: Boolean(window.DOMPurify),
  }));

  expect(
    probe.hasDOMPurify || !probe.hasTrustedTypes,
    'dist/purify.js must expose window.DOMPurify when Trusted Types exist'
  ).toBe(true);

  return probe.hasTrustedTypes && probe.hasDOMPurify;
}

test.describe('Trusted Types enforcement — attribute signing', () => {
  test.beforeEach(async ({ page }) => {
    const supported = await openHarness(page);
    test.skip(
      !supported,
      'This engine has no Trusted Types support; enforcement cannot be exercised.'
    );
  });

  test('the live attribute table types every sink this suite relies on', async ({
    page,
  }) => {
    const table = await page.evaluate(() => {
      const tt = window.trustedTypes;
      return {
        srcdoc: tt.getAttributeType('iframe', 'srcdoc'),
        scriptSrc: tt.getAttributeType('script', 'src'),
        scriptHrefSvg: tt.getAttributeType(
          'script',
          'href',
          'http://www.w3.org/2000/svg'
        ),
        scriptHrefSvgXlink: tt.getAttributeType(
          'script',
          'href',
          'http://www.w3.org/2000/svg',
          'http://www.w3.org/1999/xlink'
        ),
        divSrcdoc: tt.getAttributeType('div', 'srcdoc'),
      };
    });

    /* These four are the sinks the assertions below depend on. If an engine
       changes its table, fail here first with a clear message instead of
       letting a later test pass or fail for the wrong reason. */
    expect(table).toEqual({
      srcdoc: 'TrustedHTML',
      scriptSrc: 'TrustedScriptURL',
      scriptHrefSvg: 'TrustedScriptURL',
      scriptHrefSvgXlink: 'TrustedScriptURL',
      divSrcdoc: null,
    });
  });

  test('iframe srcdoc rewritten by sanitize is signed with TrustedHTML', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = window.DOMPurify.sanitize(
        '<iframe srcdoc="  <b>hi</b>  "></iframe>',
        { ADD_TAGS: ['iframe'], ADD_ATTR: ['srcdoc'] }
      );
      return {
        out,
        writes: window.__ttAudit.writes.slice(),
        removed: window.__ttAudit.removed(),
      };
    });

    expect(result.out).toBe('<iframe srcdoc="&lt;b&gt;hi&lt;/b&gt;"></iframe>');
    expect(result.removed).toEqual([]);

    const write = result.writes.find(
      (entry) => entry.attr === 'srcdoc' && entry.tag === 'iframe'
    );
    expect(write, 'srcdoc went through the TrustedHTML sink').toBeTruthy();
    expect(write.expected).toBe('TrustedHTML');
    expect(write.signed).toBe(true);
    expect(write.value).toBe('<b>hi</b>');
  });

  test('script src rewritten by sanitize is signed with TrustedScriptURL', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = window.DOMPurify.sanitize(
        '<div><script src="  https://example.test/a.js  "></script></div>',
        { ADD_TAGS: ['script'], ADD_ATTR: ['src'] }
      );
      return { out, writes: window.__ttAudit.writes.slice() };
    });

    expect(result.out).toBe(
      '<div><script src="https://example.test/a.js"></script></div>'
    );

    const write = result.writes.find(
      (entry) => entry.attr === 'src' && entry.tag === 'script'
    );
    expect(write).toBeTruthy();
    expect(write.expected).toBe('TrustedScriptURL');
    expect(write.signed).toBe(true);
  });

  test('dangerous srcdoc is removed before it can be signed (safe rejection)', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = window.DOMPurify.sanitize(
        '<iframe srcdoc=" javascript:alert(1) "></iframe>',
        { ADD_TAGS: ['iframe'], ADD_ATTR: ['srcdoc'] }
      );
      return {
        out,
        writes: window.__ttAudit.writes.slice(),
        removed: window.__ttAudit.removed(),
      };
    });

    expect(result.out).toBe('<iframe></iframe>');
    expect(result.removed).toContain('srcdoc');
    expect(result.writes).toEqual([]);
  });

  test('object data and embed src are signed where the engine types them', async ({
    page,
  }) => {
    const typed = await page.evaluate(() => ({
      objectData: window.trustedTypes.getAttributeType('object', 'data'),
      embedSrc: window.trustedTypes.getAttributeType('embed', 'src'),
    }));

    /* Engines disagree on this part of the table (Firefox types neither),
       so only assert where the sink is actually typed. The jsdom suite
       covers the same behaviour unconditionally via its simulator. */
    test.skip(
      !typed.objectData && !typed.embedSrc,
      'This engine does not type object/embed URL attributes.'
    );

    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = [
        window.DOMPurify.sanitize(
          '<object data="  https://example.test/frame  "></object>',
          { ADD_TAGS: ['object'], ADD_ATTR: ['data'] }
        ),
        window.DOMPurify.sanitize(
          '<embed src="  https://example.test/media  ">',
          { ADD_TAGS: ['embed'], ADD_ATTR: ['src'] }
        ),
      ].join('|');
      return { out, writes: window.__ttAudit.writes.slice() };
    });

    expect(result.out).toBe(
      '<object data="https://example.test/frame"></object>' +
        '|<embed src="https://example.test/media">'
    );

    if (typed.objectData) {
      const write = result.writes.find((entry) => entry.tag === 'object');
      expect(write.signed, 'object data is branded').toBe(true);
    }

    if (typed.embedSrc) {
      const write = result.writes.find((entry) => entry.tag === 'embed');
      expect(write.signed, 'embed src is branded').toBe(true);
    }
  });

  test('the same attribute name in a non-typed context is not branded', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = window.DOMPurify.sanitize(
        '<div srcdoc="  <b>k</b>  "></div>',
        { ADD_ATTR: ['srcdoc'] }
      );
      return { out, writes: window.__ttAudit.writes.slice() };
    });

    expect(result.out).toBe('<div srcdoc="&lt;b&gt;k&lt;/b&gt;"></div>');
    const write = result.writes.find((entry) => entry.tag === 'div');
    expect(write).toBeTruthy();
    expect(write.expected).toBe(null);
    expect(write.signed).toBe(null);
  });

  test('namespaced SVG script links are dropped, not written unsigned (safe rejection)', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = window.DOMPurify.sanitize(
        '<svg><script href="  https://example.test/a.js  "></script></svg>',
        { ADD_TAGS: ['script'], ADD_ATTR: ['href'] }
      );
      return {
        out,
        writes: window.__ttAudit.writes.slice(),
        removed: window.__ttAudit.removed(),
      };
    });

    /* DOMPurify asks getAttributeType() without the element namespace, so it
       does not brand SVG <script href>. The engine nevertheless types that
       sink by element namespace and refuses the unsigned write, so the URL is
       removed rather than left in the document unsigned. Safe rejection. */
    expect(result.out).toBe('<svg><script></script></svg>');
    expect(result.removed).toContain('href');
    const write = result.writes.find((entry) => entry.attr === 'href');
    expect(write).toBeTruthy();
    expect(write.signed).not.toBe(true);
  });

  test('an unchanged SVG script link is never written, so nothing is refused', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = window.DOMPurify.sanitize(
        '<svg><script href="https://example.test/a.js"></script></svg>',
        { ADD_TAGS: ['script'], ADD_ATTR: ['href'] }
      );
      return { out, writes: window.__ttAudit.writes.slice() };
    });

    expect(result.out).toBe(
      '<svg><script href="https://example.test/a.js"></script></svg>'
    );
    expect(result.writes).toEqual([]);
  });
});

test.describe('Trusted Types enforcement — hooks cannot bypass signing', () => {
  test.beforeEach(async ({ page }) => {
    const supported = await openHarness(page);
    test.skip(
      !supported,
      'This engine has no Trusted Types support; enforcement cannot be exercised.'
    );
  });

  test('a hook rewrite is signed before it reaches the sink', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      window.DOMPurify.addHook('uponSanitizeAttribute', (node, event) => {
        if (event.attrName === 'srcdoc') {
          event.attrValue = ' <b>hooked</b> ';
        }
      });
      const out = window.DOMPurify.sanitize('<iframe srcdoc="safe"></iframe>', {
        ADD_TAGS: ['iframe'],
        ADD_ATTR: ['srcdoc'],
      });
      window.DOMPurify.removeAllHooks();
      return { out, writes: window.__ttAudit.writes.slice() };
    });

    expect(result.out).toBe(
      '<iframe srcdoc=" &lt;b&gt;hooked&lt;/b&gt; "></iframe>'
    );
    const write = result.writes.find((entry) => entry.attr === 'srcdoc');
    expect(write).toBeTruthy();
    expect(write.signed).toBe(true);
  });

  test('a hook writing a plain string into a TT sink is refused by the engine', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      window.DOMPurify.addHook('afterSanitizeAttributes', (node) => {
        if (node.nodeName === 'IFRAME') {
          node.setAttribute('srcdoc', 'plain-string');
        }
      });
      let message = null;
      try {
        window.DOMPurify.sanitize('<iframe srcdoc="safe"></iframe>', {
          ADD_TAGS: ['iframe'],
          ADD_ATTR: ['srcdoc'],
        });
      } catch (error) {
        message = error.message;
      } finally {
        window.DOMPurify.removeAllHooks();
      }

      return { message, writes: window.__ttAudit.writes.slice() };
    });

    /* Safe rejection: the engine refuses the unsigned write with a TypeError.
       Engine wording differs - Chromium names the required type ("This
       document requires 'TrustedHTML' assignment"), Firefox reports "Sink
       type mismatch violation blocked by CSP" - so assert on the refusal
       itself plus the unsigned write record below. */
    expect(result.message).toMatch(/trustedhtml|sink type mismatch/i);
    const write = result.writes.find((entry) => entry.value === 'plain-string');
    expect(write).toBeTruthy();
    expect(write.signed).toBe(false);
  });

  test('forceKeepAttr does not create a signed write for an unvalidated value', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      window.DOMPurify.addHook('uponSanitizeAttribute', (node, event) => {
        if (event.attrName === 'srcdoc') {
          event.forceKeepAttr = true;
          event.attrValue = ' javascript:alert(3) ';
        }
      });
      const out = window.DOMPurify.sanitize(
        '<iframe srcdoc="  safe  "></iframe>',
        { ADD_TAGS: ['iframe'], ADD_ATTR: ['srcdoc'] }
      );
      window.DOMPurify.removeAllHooks();
      return { out, writes: window.__ttAudit.writes.slice() };
    });

    /* Compatible behaviour: forceKeepAttr stops DOMPurify from touching the
       attribute, so the parsed value survives and the hook value is not
       applied. The invariant that matters: the dangerous value was never
       written to the sink under any brand. */
    expect(result.out).toBe('<iframe srcdoc="  safe  "></iframe>');
    expect(result.writes).toEqual([]);
    expect(
      result.writes.some((entry) => entry.value.includes('javascript:'))
    ).toBe(false);
  });
});

test.describe('Trusted Types enforcement — configuration cannot opt out silently', () => {
  test.beforeEach(async ({ page }) => {
    const supported = await openHarness(page);
    test.skip(
      !supported,
      'This engine has no Trusted Types support; enforcement cannot be exercised.'
    );
  });

  test('TRUSTED_TYPES_POLICY: null returns nothing unsigned (safe rejection)', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = window.DOMPurify.sanitize(
        '<iframe srcdoc="  <b>q</b>  "></iframe>',
        {
          ADD_TAGS: ['iframe'],
          ADD_ATTR: ['srcdoc'],
          TRUSTED_TYPES_POLICY: null,
        }
      );
      return { out, writes: window.__ttAudit.writes.slice() };
    });

    expect(result.out).toBe('');
    expect(result.out).not.toContain('<b>q</b>');
    expect(result.writes).toEqual([]);
  });

  test('TRUSTED_TYPES_POLICY: null passes plain text through', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = window.DOMPurify.sanitize('plain text', {
        TRUSTED_TYPES_POLICY: null,
      });
      return { out, writes: window.__ttAudit.writes.slice() };
    });

    expect(result.out).toBe('plain text');
    expect(result.writes).toEqual([]);
  });

  test('a policy returning plain strings cannot smuggle unsigned markup', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const out = window.DOMPurify.sanitize(
        '<iframe srcdoc="  <b>q</b>  "></iframe>',
        {
          ADD_TAGS: ['iframe'],
          ADD_ATTR: ['srcdoc'],
          TRUSTED_TYPES_POLICY: {
            createHTML: (input) => input,
            createScriptURL: (input) => input,
          },
        }
      );
      return { out, writes: window.__ttAudit.writes.slice() };
    });

    /* Safe rejection: the parser refuses the unsigned markup. */
    expect(result.out).toBe('');
    expect(result.out).not.toContain('<b>q</b>');
  });

  test('a policy minting the wrong brand cannot satisfy a TrustedHTML sink', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const fixture = window.__ttAudit.fixture();
      const out = window.DOMPurify.sanitize(
        '<iframe srcdoc="  <b>x</b>  "></iframe>',
        {
          ADD_TAGS: ['iframe'],
          ADD_ATTR: ['srcdoc'],
          TRUSTED_TYPES_POLICY: {
            createHTML(input) {
              if (String(input) === '<b>x</b>') {
                return fixture.createScriptURL('https://example.test/not-html');
              }

              return fixture.createHTML(input);
            },
            createScriptURL: (input) => fixture.createScriptURL(input),
          },
        }
      );
      return {
        out,
        writes: window.__ttAudit.writes.slice(),
        removed: window.__ttAudit.removed(),
      };
    });

    /* Safe rejection: the engine checks the brand per sink, refuses the
       mismatched TrustedScriptURL, and DOMPurify removes the attribute. */
    expect(result.out).toBe('<iframe></iframe>');
    expect(result.removed).toContain('srcdoc');
    const write = result.writes.find((entry) => entry.attr === 'srcdoc');
    expect(write).toBeTruthy();
    expect(write.expected).toBe('TrustedHTML');
    expect(write.signed).toBe(false);
  });

  test('clearConfig restores the internal policy after a caller policy signs', async ({
    page,
  }) => {
    const result = await page.evaluate(() => {
      window.__ttAudit.reset();
      const caller = window.trustedTypes.createPolicy('tt-browser-suite', {
        createHTML: (input) => input,
        createScriptURL: (input) => input,
      });
      const cfg = { ADD_TAGS: ['iframe'], ADD_ATTR: ['srcdoc'] };

      window.DOMPurify.setConfig(
        Object.assign({ TRUSTED_TYPES_POLICY: caller }, cfg)
      );
      const first = window.DOMPurify.sanitize(
        '<iframe srcdoc="  <b>one</b>  "></iframe>'
      );
      window.DOMPurify.clearConfig();
      const second = window.DOMPurify.sanitize(
        '<iframe srcdoc="  <b>two</b>  "></iframe>',
        cfg
      );

      return {
        out: String(first) + '|' + String(second),
        writes: window.__ttAudit.writes.slice(),
      };
    });

    expect(result.out).toBe(
      '<iframe srcdoc="&lt;b&gt;one&lt;/b&gt;"></iframe>' +
        '|<iframe srcdoc="&lt;b&gt;two&lt;/b&gt;"></iframe>'
    );
    const writes = result.writes.filter((entry) => entry.attr === 'srcdoc');
    expect(writes.length).toBe(2);
    expect(writes.every((entry) => entry.signed === true)).toBe(true);
  });
});
