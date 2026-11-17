/*
 * Trusted Types attribute-signing suite.
 *
 * Scope
 * -----
 * When a page enforces Trusted Types (`require-trusted-types-for 'script'`),
 * the browser rejects every write of an unsigned string into a Trusted Types
 * sink. DOMPurify therefore has to hand the DOM a *branded* value for every
 * attribute the browser types as TrustedHTML / TrustedScriptURL. If it writes
 * a plain string instead, the engine blocks the write; DOMPurify catches that
 * TypeError and removes the attribute.
 *
 * This suite pins the contract down attribute by attribute:
 *
 *   1. Allowed, TT-typed attributes are signed with the brand the browser
 *      demands, and dangerous values never reach the signing policy.
 *   2. Hooks and configuration changes cannot bypass enforcement. Every test
 *      says whether the observed outcome is a *safe rejection* (attribute
 *      removed / engine refused the write / nothing unsigned returned) or a
 *      *compatible behaviour* (sanitized output is the expected string). The
 *      two must not be confused: a removed attribute and a silently unsigned
 *      attribute both "look fine" in a string comparison.
 *
 * How enforcement is reproduced
 * -----------------------------
 * jsdom has no Trusted Types support, so this module installs a simulator
 * into a *fresh* realm before dist/purify.js is evaluated there:
 *
 *   - `window.trustedTypes.createPolicy()` returns branded wrapper objects,
 *     like the engine (the callback's return value is wrapped, never trusted
 *     as a brand itself).
 *   - `getAttributeType()` mirrors Chromium's attribute table for the sinks
 *     DOMPurify can emit.
 *   - `Element.prototype.setAttribute` / `setAttributeNS`, the `innerHTML`
 *     setter and `DOMParser.prototype.parseFromString` refuse unsigned values
 *     for TT-typed sinks with the same TypeError the engine raises.
 *
 * Every attempted write, refusal and policy call lands in `window.__ttAudit`,
 * which the tests assert on. Enforcement is simulated at the *sink*, not at
 * the policy: having created a policy is not enough, the value written to the
 * sink must carry the matching brand.
 *
 * The scenarios are re-run against real Chromium enforcement (with a real
 * `require-trusted-types-for` CSP) in test/trusted-types-browser.spec.js.
 * Keep the two in sync.
 */

(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined'
    ? (module.exports = factory())
    : typeof define === 'function' && define.amd
      ? define(factory)
      : ((global =
          typeof globalThis !== 'undefined' ? globalThis : global || self),
        (global.trustedTypesAttributeSuite = factory()));
})(this, function () {
  const fs = require('fs');

  const HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml';
  const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';
  const XLINK_NAMESPACE = 'http://www.w3.org/1999/xlink';

  /*
   * The TT-typed attributes DOMPurify can reach, as Chromium reports them.
   * The live table is asserted in test/trusted-types-browser.spec.js.
   *
   * Note the element-namespace requirement for SVG <script href>: with two
   * arguments `getAttributeType('script', 'href')` is null, only the SVG
   * context (or the XLink attribute namespace) types it. DOMPurify calls it
   * without namespaces, which is why the SVG case below is a rejection.
   */
  const getAttributeType = function (tag, attr, elementNs, attrNs) {
    const lcTag = String(tag).toLowerCase();
    const lcAttr = String(attr).toLowerCase();

    if (lcTag === 'iframe' && lcAttr === 'srcdoc') {
      return 'TrustedHTML';
    }

    if (lcTag === 'script' && lcAttr === 'src') {
      return 'TrustedScriptURL';
    }

    if (
      lcTag === 'script' &&
      lcAttr === 'href' &&
      (elementNs === SVG_NAMESPACE || attrNs === XLINK_NAMESPACE)
    ) {
      return 'TrustedScriptURL';
    }

    if (lcTag === 'object' && (lcAttr === 'data' || lcAttr === 'codebase')) {
      return 'TrustedScriptURL';
    }

    if (lcTag === 'embed' && lcAttr === 'src') {
      return 'TrustedScriptURL';
    }

    return null;
  };

  const createBrands = function () {
    class TrustedHTML {
      constructor(value) {
        this.value = String(value);
      }

      toString() {
        return this.value;
      }
    }

    class TrustedScriptURL {
      constructor(value) {
        this.value = String(value);
      }

      toString() {
        return this.value;
      }
    }

    return {
      TrustedHTML,
      TrustedScriptURL,
      isHTML: (value) => value instanceof TrustedHTML,
      isScriptURL: (value) => value instanceof TrustedScriptURL,
    };
  };

  /* Installs the enforcement simulator into `window`. */
  const installEnforcement = function (window) {
    const brands = createBrands();
    const { TrustedHTML, TrustedScriptURL } = brands;

    const audit = {
      writes: [],
      blocked: [],
      policyCalls: [],
      policies: [],
      reset() {
        this.writes.length = 0;
        this.blocked.length = 0;
        this.policyCalls.length = 0;
        this.policies.length = 0;
      },
      writesFor(attr) {
        return this.writes.filter((write) => write.attr === attr);
      },
    };

    const brandFor = function (type, value) {
      if (type === 'TrustedHTML') {
        return brands.isHTML(value);
      }

      if (type === 'TrustedScriptURL') {
        return brands.isScriptURL(value);
      }

      return false;
    };

    /* Reads the live table, so a test can swap in a custom mapping. */
    const attributeTypeFor = function (tag, attr, elementNs, attrNs) {
      return trustedTypes.getAttributeType(tag, attr, elementNs, attrNs);
    };

    /* Records a write attempt and throws exactly where the engine would. */
    const enforce = function (kind, element, sinkName, localName, value) {
      const tag = String(element.nodeName).toLowerCase();
      const elementNs = element.namespaceURI || HTML_NAMESPACE;
      const attrNs = kind === 'setAttributeNS' ? sinkName : null;
      const expected = attributeTypeFor(
        tag,
        localName,
        elementNs,
        attrNs || undefined
      );

      const record = {
        sink: kind,
        tag,
        attr: localName,
        elementNamespace: elementNs,
        attributeNamespace: attrNs || null,
        expected,
        signed: expected ? brandFor(expected, value) : null,
        value: String(value),
      };

      audit.writes.push(record);

      if (expected && !record.signed) {
        /* Same message shape as Chromium; DOMPurify's _setAttributeValue
           catches the TypeError and removes the attribute. */
        audit.blocked.push(record);
        throw new window.TypeError(
          "Failed to execute '" +
            kind +
            "' on 'Element': This document requires '" +
            expected +
            "' assignment."
        );
      }

      return value;
    };

    const trustedTypes = {
      createPolicy(name, rules) {
        audit.policies.push(name);

        /* Like the engine: the callback's return value is stringified and
           wrapped. A policy can therefore never mint a *wrong* brand; only a
           hand-rolled fake policy object can. */
        const policy = {
          name,
          createHTML(input) {
            const output = (rules.createHTML || String)(input);
            audit.policyCalls.push({
              policy: name,
              type: 'TrustedHTML',
              input: String(input),
            });
            return new TrustedHTML(output);
          },
          createScriptURL(input) {
            const output = (rules.createScriptURL || String)(input);
            audit.policyCalls.push({
              policy: name,
              type: 'TrustedScriptURL',
              input: String(input),
            });
            return new TrustedScriptURL(output);
          },
        };

        return policy;
      },
      getAttributeType,
      isHTML: brands.isHTML,
      isScriptURL: brands.isScriptURL,
    };

    window.trustedTypes = trustedTypes;

    const elementPrototype = window.Element.prototype;
    const originalSetAttribute = elementPrototype.setAttribute;
    const originalSetAttributeNS = elementPrototype.setAttributeNS;

    elementPrototype.setAttribute = function (name, value) {
      const localName = String(name).toLowerCase();
      enforce('setAttribute', this, name, localName, value);
      return originalSetAttribute.call(this, name, String(value));
    };

    elementPrototype.setAttributeNS = function (namespaceURI, name, value) {
      const localName = String(name).split(':').pop().toLowerCase();
      enforce('setAttributeNS', this, namespaceURI, localName, value);
      return originalSetAttributeNS.call(
        this,
        namespaceURI,
        name,
        String(value)
      );
    };

    /* `innerHTML` is a TrustedHTML sink in every engine that enforces TT. */
    const innerHTMLDescriptor = Object.getOwnPropertyDescriptor(
      window.Element.prototype,
      'innerHTML'
    );

    if (innerHTMLDescriptor && innerHTMLDescriptor.set) {
      const originalSetInnerHTML = innerHTMLDescriptor.set;
      const originalGetInnerHTML = innerHTMLDescriptor.get;
      Object.defineProperty(window.Element.prototype, 'innerHTML', {
        configurable: true,
        enumerable: innerHTMLDescriptor.enumerable,
        get: originalGetInnerHTML,
        set(value) {
          if (!brands.isHTML(value)) {
            audit.blocked.push({
              sink: 'innerHTML',
              tag: String(this.nodeName).toLowerCase(),
              attr: 'innerHTML',
              expected: 'TrustedHTML',
              signed: false,
              value: String(value),
            });
            throw new window.TypeError(
              "Failed to set the 'innerHTML' property on 'Element': " +
                "This document requires 'TrustedHTML' assignment."
            );
          }

          originalSetInnerHTML.call(this, String(value));
        },
      });
    }

    /* DOMParser.parseFromString takes TrustedHTML as well. */
    if (window.DOMParser) {
      const originalParseFromString =
        window.DOMParser.prototype.parseFromString;
      window.DOMParser.prototype.parseFromString = function (markup, type) {
        if (!brands.isHTML(markup)) {
          audit.blocked.push({
            sink: 'parseFromString',
            tag: 'DOMParser',
            attr: type,
            expected: 'TrustedHTML',
            signed: false,
            value: String(markup),
          });
          throw new window.TypeError(
            "Failed to execute 'parseFromString' on 'DOMParser': " +
              "This document requires 'TrustedHTML' assignment."
          );
        }

        return originalParseFromString.call(this, String(markup), type);
      };
    }

    window.__ttAudit = audit;

    return { audit, trustedTypes, brands };
  };

  /*
   * Creates a fresh realm with enforcement installed *before* DOMPurify is
   * loaded. A fresh realm per test is needed because policy names are unique
   * per realm and the sink patches are realm-global.
   *
   * `options.attributeTypes` replaces the attribute table, so a test can model
   * a sink DOMPurify has no signing branch for (e.g. a future TrustedScript
   * attribute). `options.beforeLoad` runs right after enforcement is installed
   * and before dist/purify.js is evaluated.
   */
  const createRealm = function (JSDOM, options) {
    const settings = options || {};
    const { window } = new JSDOM('<head></head>', {
      runScripts: 'dangerously',
    });

    const enforcement = installEnforcement(window);

    if (settings.attributeTypes) {
      enforcement.trustedTypes.getAttributeType = settings.attributeTypes;
    }

    /* A fixture policy lets tests mint branded values (innerHTML enforced). */
    const fixturePolicy = window.trustedTypes.createPolicy('tt-suite-fixture', {
      createHTML: (input) => input,
      createScriptURL: (input) => input,
    });

    if (settings.beforeLoad) {
      settings.beforeLoad(window, fixturePolicy);
    }

    const library = fs.readFileSync('dist/purify.js', { encoding: 'utf8' });
    const scriptEl = window.document.createElement('script');
    scriptEl.textContent = library;
    window.document.body.appendChild(scriptEl);

    enforcement.audit.reset();

    return {
      window,
      DOMPurify: window.DOMPurify,
      audit: enforcement.audit,
      trustedTypes: enforcement.trustedTypes,
      brands: enforcement.brands,
      fixturePolicy,
    };
  };

  return function trustedTypesAttributeSuite(JSDOM) {
    const IFrameConfig = {
      ADD_TAGS: ['iframe'],
      ADD_ATTR: ['srcdoc'],
    };

    const ScriptConfig = {
      ADD_TAGS: ['script'],
      ADD_ATTR: ['src'],
    };

    const signedWriteOn = function (audit, attr, expected) {
      return audit.writes.find(
        (write) => write.attr === attr && write.expected === expected
      );
    };

    // =====================================================================
    // Signing - allowed attributes ARE branded for the sink that takes them
    // =====================================================================

    QUnit.module('Trusted Types - attribute signing (allowed paths)');

    QUnit.test(
      'iframe srcdoc rewritten by sanitize is signed with TrustedHTML',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc="  <b>hi</b>  "></iframe>',
          IFrameConfig
        );

        assert.equal(
          clean,
          '<iframe srcdoc="&lt;b&gt;hi&lt;/b&gt;"></iframe>',
          'compatible behaviour: trimmed and escaped, attribute kept'
        );
        assert.equal(audit.blocked.length, 0, 'no write was refused');

        const write = signedWriteOn(audit, 'srcdoc', 'TrustedHTML');
        assert.ok(write, 'srcdoc went through the TrustedHTML sink');
        assert.equal(
          write.signed,
          true,
          'the written value carried the TrustedHTML brand'
        );
        assert.equal(
          write.value,
          '<b>hi</b>',
          'the signed value is the sanitized value, not the raw input'
        );
      }
    );

    QUnit.test(
      'script src rewritten by sanitize is signed with TrustedScriptURL',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        const clean = DOMPurify.sanitize(
          '<div><script src="  https://example.test/a.js  "></script></div>',
          ScriptConfig
        );

        assert.equal(
          clean,
          '<div><script src="https://example.test/a.js"></script></div>',
          'compatible behaviour: trimmed URL survives'
        );
        assert.equal(audit.blocked.length, 0, 'no write was refused');

        const write = signedWriteOn(audit, 'src', 'TrustedScriptURL');
        assert.ok(write, 'src went through the TrustedScriptURL sink');
        assert.equal(
          write.signed,
          true,
          'the written value carried the TrustedScriptURL brand'
        );
      }
    );

    QUnit.test(
      'other TT-typed attributes (object data, embed src) are signed too',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        const object = DOMPurify.sanitize(
          '<object data="  https://example.test/frame  "></object>',
          { ADD_TAGS: ['object'], ADD_ATTR: ['data'] }
        );
        assert.equal(
          object,
          '<object data="https://example.test/frame"></object>',
          'compatible behaviour: object data is rewritten'
        );

        const embed = DOMPurify.sanitize(
          '<embed src="  https://example.test/media  ">',
          { ADD_TAGS: ['embed'], ADD_ATTR: ['src'] }
        );
        assert.equal(
          embed,
          '<embed src="https://example.test/media">',
          'compatible behaviour: embed src is rewritten'
        );

        assert.equal(audit.blocked.length, 0, 'no write was refused');
        assert.equal(
          audit.writesFor('data').every((write) => write.signed === true),
          true,
          'object data was branded'
        );
        assert.equal(
          audit.writesFor('src').every((write) => write.signed === true),
          true,
          'embed src was branded'
        );
      }
    );

    QUnit.test(
      'the configured TRUSTED_TYPES_POLICY signs attributes, not the internal one',
      function (assert) {
        const { window, DOMPurify, audit } = createRealm(JSDOM);

        const callerPolicy = window.trustedTypes.createPolicy('caller-policy', {
          createHTML: (input) => input,
          createScriptURL: (input) => input,
        });
        audit.reset();

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc="  <b>x</b>  "></iframe>',
          Object.assign({ TRUSTED_TYPES_POLICY: callerPolicy }, IFrameConfig)
        );

        assert.equal(
          clean,
          '<iframe srcdoc="&lt;b&gt;x&lt;/b&gt;"></iframe>',
          'compatible behaviour: the attribute is signed and kept'
        );
        assert.equal(audit.blocked.length, 0, 'no write was refused');

        const call = audit.policyCalls.find(
          (entry) => entry.type === 'TrustedHTML' && entry.input === '<b>x</b>'
        );
        assert.ok(call, 'the attribute value went through a policy');
        assert.equal(
          call.policy,
          'caller-policy',
          'the caller-supplied policy signed the attribute'
        );
        assert.notOk(
          audit.policies.includes('dompurify'),
          'no internal policy was created while the caller policy was active'
        );
      }
    );

    QUnit.test(
      'the internal dompurify policy is created once and signs every write',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        DOMPurify.sanitize(
          '<iframe srcdoc="  <b>one</b>  "></iframe>',
          IFrameConfig
        );
        DOMPurify.sanitize(
          '<iframe srcdoc="  <b>two</b>  "></iframe>',
          IFrameConfig
        );

        assert.equal(
          audit.policies.filter((name) => name === 'dompurify').length,
          1,
          'internal policy created exactly once per realm'
        );
        const writes = audit.writesFor('srcdoc');
        assert.equal(writes.length, 2, 'two attribute writes happened');
        assert.equal(
          writes.every((write) => write.signed === true),
          true,
          'both writes were branded'
        );
      }
    );

    // =====================================================================
    // Rejection - dangerous values and wrong contexts never become signed
    // =====================================================================

    QUnit.module('Trusted Types - attribute signing (rejection paths)');

    QUnit.test(
      'dangerous srcdoc values are removed before any policy sees them',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc=" javascript:alert(1) "></iframe>',
          IFrameConfig
        );

        assert.equal(
          clean,
          '<iframe></iframe>',
          'safe rejection: the attribute is gone'
        );
        assert.deepEqual(
          audit.writesFor('srcdoc'),
          [],
          'the dangerous value never reached a sink'
        );
        /* The parse-time createHTML(dirty) call necessarily carries the raw
           input, dangerous attribute included - that signature belongs to the
           parser sink, not to the attribute. What must never happen is the
           attribute *value* being signed on its own for a later write. */
        assert.notOk(
          audit.policyCalls.some(
            (call) => call.input === 'javascript:alert(1)'
          ),
          'the attribute value was never signed as an attribute value'
        );
        assert.ok(
          DOMPurify.removed.some(
            (entry) => entry.attribute && entry.attribute.name === 'srcdoc'
          ),
          'the removal is reported'
        );
      }
    );

    QUnit.test(
      'unsafe script src is removed rather than signed',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        const clean = DOMPurify.sanitize(
          '<div><script src="javascript:alert(2)"></script></div>',
          ScriptConfig
        );

        assert.equal(
          clean,
          '<div><script></script></div>',
          'safe rejection: src is gone'
        );
        assert.deepEqual(
          audit.writesFor('src'),
          [],
          'no write happened, so nothing was signed'
        );
        assert.notOk(
          audit.policyCalls.some(
            (call) => call.input === 'javascript:alert(2)'
          ),
          'the unsafe URL was never signed as an attribute value'
        );
      }
    );

    QUnit.test(
      'the same attribute name in a non-typed context stays a plain string',
      function (assert) {
        const { DOMPurify, audit, trustedTypes } = createRealm(JSDOM);

        assert.equal(
          trustedTypes.getAttributeType('div', 'srcdoc'),
          null,
          'div@srcdoc is not a TT sink'
        );

        const clean = DOMPurify.sanitize('<div srcdoc="  <b>k</b>  "></div>', {
          ADD_ATTR: ['srcdoc'],
        });

        assert.equal(
          clean,
          '<div srcdoc="&lt;b&gt;k&lt;/b&gt;"></div>',
          'compatible behaviour: the attribute is kept as a normal string'
        );

        const write = audit
          .writesFor('srcdoc')
          .find((entry) => entry.tag === 'div');
        assert.ok(write, 'the rewritten value was written');
        assert.equal(
          write.expected,
          null,
          'wrong context: the engine types nothing here'
        );
        assert.equal(write.signed, null, 'no brand was attached');
      }
    );

    QUnit.test(
      'a policy minting the wrong brand cannot satisfy a TrustedHTML sink',
      function (assert) {
        const { DOMPurify, audit, fixturePolicy } = createRealm(JSDOM);

        /* A hand-rolled policy object (not from createPolicy) can return a
           TrustedScriptURL where TrustedHTML is required. Type checking is
           per sink, so the engine refuses the write. */
        const wrongBrandPolicy = {
          createHTML(input) {
            if (String(input) === '<b>x</b>') {
              return fixturePolicy.createScriptURL(
                'https://example.test/not-html'
              );
            }

            return fixturePolicy.createHTML(input);
          },
          createScriptURL: (input) => fixturePolicy.createScriptURL(input),
        };

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc="  <b>x</b>  "></iframe>',
          Object.assign(
            { TRUSTED_TYPES_POLICY: wrongBrandPolicy },
            IFrameConfig
          )
        );

        assert.equal(
          clean,
          '<iframe></iframe>',
          'safe rejection: the mismatched brand is refused, attribute removed'
        );
        assert.equal(audit.blocked.length, 1, 'exactly one write was refused');
        assert.equal(
          audit.blocked[0].expected,
          'TrustedHTML',
          'the refusal is for the TrustedHTML sink'
        );
        assert.equal(
          audit.blocked[0].signed,
          false,
          'the refused value carried the wrong brand'
        );
      }
    );

    QUnit.test(
      'namespaced SVG script links are dropped, not written unsigned',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        /* DOMPurify queries getAttributeType() without the element
           namespace, so it does not sign SVG <script href> (see the comment
           on _applyTrustedTypesToAttribute). When the value needs a rewrite,
           the engine refuses the unsigned write and DOMPurify removes the
           attribute: safe rejection, not a bypass. */
        const clean = DOMPurify.sanitize(
          '<svg><script href="  https://example.test/a.js  "></script></svg>',
          { ADD_TAGS: ['script'], ADD_ATTR: ['href'] }
        );

        assert.equal(
          clean,
          '<svg><script></script></svg>',
          'safe rejection: no unsigned URL survives'
        );
        assert.equal(
          audit.blocked.length,
          1,
          'the engine refused the unsigned write'
        );
        assert.equal(
          audit.blocked[0].expected,
          'TrustedScriptURL',
          'the refusal names the URL sink'
        );
      }
    );

    QUnit.test(
      'an unchanged SVG script link is never written, so nothing is refused',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        /* The complement of the test above: when sanitize() does not rewrite
           the value, DOMPurify never calls setAttribute, so the unsigned
           parsed attribute simply stays as parsed. */
        const clean = DOMPurify.sanitize(
          '<svg><script href="https://example.test/a.js"></script></svg>',
          { ADD_TAGS: ['script'], ADD_ATTR: ['href'] }
        );

        assert.equal(
          clean,
          '<svg><script href="https://example.test/a.js"></script></svg>',
          'compatible behaviour: the parsed value is preserved'
        );
        assert.deepEqual(audit.writesFor('href'), [], 'no write happened');
        assert.equal(audit.blocked.length, 0, 'nothing was refused');
      }
    );

    QUnit.test(
      'a sink typed as a brand DOMPurify cannot mint is safely dropped',
      function (assert) {
        /* Model a future/host-specific TT attribute that maps to TrustedScript,
           which DOMPurify has no policy method for (only createHTML and
           createScriptURL are part of the configurable policy contract). The
           value must not be written unsigned and must not be silently kept:
           safe rejection, same as an engine-side type mismatch. */
        const { DOMPurify, audit } = createRealm(JSDOM, {
          attributeTypes(tag, attr) {
            if (tag === 'iframe' && attr === 'srcdoc') {
              return 'TrustedScript';
            }

            return null;
          },
        });

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc="  <b>q</b>  "></iframe>',
          IFrameConfig
        );

        assert.equal(
          clean,
          '<iframe></iframe>',
          'safe rejection: the attribute is dropped'
        );
        const write = audit.writesFor('srcdoc')[0];
        assert.ok(write, 'DOMPurify tried the write');
        assert.equal(
          write.expected,
          'TrustedScript',
          'the sink wants TrustedScript'
        );
        assert.equal(write.signed, false, 'the write was unsigned');
        assert.equal(audit.blocked.length, 1, 'the engine refused it');
        assert.ok(
          DOMPurify.removed.some(
            (entry) => entry.attribute && entry.attribute.name === 'srcdoc'
          ),
          'the refusal is reported in DOMPurify.removed'
        );
      }
    );

    // =====================================================================
    // Hooks - cannot bypass the sink
    // =====================================================================

    QUnit.module('Trusted Types - attribute signing (hooks)');

    QUnit.test(
      'a hook rewrite is signed, so hooks cannot bypass enforcement',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        DOMPurify.addHook('uponSanitizeAttribute', (node, event) => {
          if (event.attrName === 'srcdoc') {
            event.attrValue = ' <b>hooked</b> ';
          }
        });

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc="safe"></iframe>',
          IFrameConfig
        );

        assert.equal(
          clean,
          '<iframe srcdoc=" &lt;b&gt;hooked&lt;/b&gt; "></iframe>',
          'compatible behaviour: the hook value is used and escaped'
        );
        assert.equal(audit.blocked.length, 0, 'no write was refused');

        const write = signedWriteOn(audit, 'srcdoc', 'TrustedHTML');
        assert.ok(write, 'the hook value went through the TT sink');
        assert.equal(write.signed, true, 'the hook value was signed');
        assert.equal(write.value, ' <b>hooked</b> ');
      }
    );

    QUnit.test(
      'a hook writing a plain string straight into a TT sink is refused',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        DOMPurify.addHook('afterSanitizeAttributes', (node) => {
          if (node.nodeName === 'IFRAME') {
            node.setAttribute('srcdoc', 'plain-string');
          }
        });

        assert.throws(
          () => {
            DOMPurify.sanitize('<iframe srcdoc="safe"></iframe>', IFrameConfig);
          },
          /TrustedHTML/,
          'safe rejection: the sink refuses the unsigned hook write'
        );
        assert.equal(
          audit.blocked.length,
          1,
          'the refusal is recorded against the hook write'
        );
        assert.equal(
          audit.blocked[0].value,
          'plain-string',
          'the refused value is the one the hook wrote'
        );
      }
    );

    QUnit.test(
      'a hook writing a signed value straight into a TT sink succeeds',
      function (assert) {
        const { DOMPurify, audit, fixturePolicy } = createRealm(JSDOM);

        DOMPurify.addHook('afterSanitizeAttributes', (node) => {
          if (node.nodeName === 'IFRAME') {
            node.setAttribute(
              'srcdoc',
              fixturePolicy.createHTML('<b>signed</b>')
            );
          }
        });

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc="safe"></iframe>',
          IFrameConfig
        );

        assert.equal(
          clean,
          '<iframe srcdoc="&lt;b&gt;signed&lt;/b&gt;"></iframe>',
          'compatible behaviour: the signed hook value is written'
        );
        assert.equal(audit.blocked.length, 0, 'nothing was refused');
        const writes = audit.writesFor('srcdoc');
        assert.equal(writes.length, 2, 'initial write plus the hook write');
        assert.equal(
          writes.every((write) => write.signed === true),
          true,
          'both writes carried the TrustedHTML brand'
        );
      }
    );

    QUnit.test(
      'forceKeepAttr skips the write and cannot rebrand an unsigned value',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        DOMPurify.addHook('uponSanitizeAttribute', (node, event) => {
          if (event.attrName === 'srcdoc') {
            event.forceKeepAttr = true;
            event.attrValue = ' javascript:alert(3) ';
          }
        });

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc="  safe  "></iframe>',
          IFrameConfig
        );

        /* forceKeepAttr is the documented hook escape hatch: DOMPurify stops
           touching the attribute, so the parsed value is what survives and
           the hook's attrValue is not applied. Crucially it does not create a
           signed write for a value the sanitizer never validated - there is
           no write at all. Compare "a hook rewrite is signed" above, where the
           same hook without forceKeepAttr produces a branded write. */
        assert.equal(
          clean,
          '<iframe srcdoc="  safe  "></iframe>',
          'compatible behaviour: the parsed (untrimmed) value is preserved'
        );
        assert.deepEqual(
          audit.writesFor('srcdoc'),
          [],
          'DOMPurify performed no sink write for the kept attribute'
        );
        assert.equal(audit.blocked.length, 0, 'nothing unsigned was attempted');
        assert.notOk(
          audit.policyCalls.some((call) => call.input.includes('javascript:')),
          'the hook value was never signed into the document'
        );
      }
    );

    // =====================================================================
    // Configuration - sticky policies cannot sign later calls
    // =====================================================================

    QUnit.module('Trusted Types - attribute signing (configuration)');

    QUnit.test(
      'TRUSTED_TYPES_POLICY: null creates no policy and returns nothing unsigned',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc="  <b>q</b>  "></iframe>',
          Object.assign({ TRUSTED_TYPES_POLICY: null }, IFrameConfig)
        );

        /* Opting out means DOMPurify signs nothing, so under enforcement the
           HTML parser itself refuses the unsigned markup. The result is the
           empty string - a safe rejection, not an unsigned document. */
        assert.equal(
          clean,
          '',
          'safe rejection: no unsigned markup is returned'
        );
        assert.notOk(
          audit.policies.includes('dompurify'),
          'opting out creates no internal policy'
        );
        assert.ok(
          audit.blocked.length > 0,
          'the engine refused the unsigned markup'
        );
        assert.ok(
          audit.blocked.every((entry) => entry.expected === 'TrustedHTML'),
          'every refusal is a TrustedHTML assignment'
        );
      }
    );

    QUnit.test(
      'TRUSTED_TYPES_POLICY: null passes plain text through without a policy',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        /* No '<' means no parse and no sink write, so there is nothing to
           refuse and nothing to sign. */
        const clean = DOMPurify.sanitize('plain text', {
          TRUSTED_TYPES_POLICY: null,
        });

        assert.equal(clean, 'plain text', 'the string is returned unchanged');
        assert.equal(audit.blocked.length, 0, 'no sink write was needed');
        assert.notOk(
          audit.policies.includes('dompurify'),
          'no internal policy was created'
        );
      }
    );

    QUnit.test(
      'a policy returning plain strings cannot smuggle unsigned markup',
      function (assert) {
        const { DOMPurify, audit } = createRealm(JSDOM);

        /* A foreign/unsafe policy object that is not backed by the real API.
           Its "branded" results are plain strings, so the parser refuses
           them; nothing unsigned reaches a sink. */
        const plainStringPolicy = {
          createHTML: (input) => input,
          createScriptURL: (input) => input,
        };

        const clean = DOMPurify.sanitize(
          '<iframe srcdoc="  <b>q</b>  "></iframe>',
          Object.assign(
            { TRUSTED_TYPES_POLICY: plainStringPolicy },
            IFrameConfig
          )
        );

        assert.equal(
          clean,
          '',
          'safe rejection: unsigned markup is refused, nothing returned'
        );
        assert.notOk(clean.includes('<b>q</b>'), 'the value never appears');
        assert.ok(
          audit.blocked.some((entry) => entry.sink === 'parseFromString'),
          'the parser refused the unsigned input'
        );
        assert.equal(
          audit.writes.filter((write) => write.signed === false).length,
          0,
          'no unsigned attribute write was attempted'
        );
      }
    );

    QUnit.test(
      'setConfig with a caller policy signs, clearConfig restores the internal one',
      function (assert) {
        const { window, DOMPurify, audit } = createRealm(JSDOM);

        const callerPolicy = window.trustedTypes.createPolicy('sticky-caller', {
          createHTML: (input) => input,
          createScriptURL: (input) => input,
        });

        DOMPurify.setConfig(
          Object.assign({ TRUSTED_TYPES_POLICY: callerPolicy }, IFrameConfig)
        );
        audit.reset();

        const first = DOMPurify.sanitize(
          '<iframe srcdoc="  <b>one</b>  "></iframe>'
        );
        assert.equal(
          first,
          '<iframe srcdoc="&lt;b&gt;one&lt;/b&gt;"></iframe>',
          'compatible behaviour: the configured policy signs'
        );
        assert.ok(
          audit.policyCalls.some(
            (call) =>
              call.policy === 'sticky-caller' && call.input === '<b>one</b>'
          ),
          'the configured policy signed the attribute'
        );

        DOMPurify.clearConfig();
        audit.reset();

        const second = DOMPurify.sanitize(
          '<iframe srcdoc="  <b>two</b>  "></iframe>',
          IFrameConfig
        );
        assert.equal(
          second,
          '<iframe srcdoc="&lt;b&gt;two&lt;/b&gt;"></iframe>',
          'compatible behaviour: sanitization still works after clearConfig'
        );
        assert.ok(
          audit.policyCalls.some(
            (call) => call.policy === 'dompurify' && call.input === '<b>two</b>'
          ),
          'the internal policy signs after clearConfig'
        );
        assert.notOk(
          audit.policyCalls.some((call) => call.policy === 'sticky-caller'),
          'the caller policy no longer signs anything'
        );
        assert.equal(audit.blocked.length, 0, 'nothing was refused');
      }
    );
  };
});
