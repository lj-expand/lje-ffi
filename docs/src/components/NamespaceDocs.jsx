import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from "remark-gfm";
import styles from './NamespaceDocs.module.css';

function Markdown({ children }) {
  if (!children) return null;
  return <ReactMarkdown remarkPlugins={[remarkGfm]}>{children}</ReactMarkdown>;
}

function buildSignature(namespace, func) {
  const base = namespace === 'base' ? 'ffi' : `ffi.${namespace}`;
  const params = func.params
    .map(p => p.optional ? `${p.name}?` : p.name)
    .join(', ');
  return `${base}.${func.name}(${params})`;
}

function NoteBanner({ note }) {
  if (!note) return null;
  return (
    <div className={styles.note}>
      <span><strong>Note:</strong> {note}</span>
    </div>
  );
}

function DeprecatedBanner({ deprecated }) {
  if (!deprecated) return null;
  const message = typeof deprecated === 'string' ? deprecated : 'This function is deprecated and may be removed in a future version.';
  return (
    <div className={styles.deprecated}>
      <span><strong>Deprecated:</strong> {message}</span>
    </div>
  );
}

function buildMethodSignature(receiver, method) {
  const params = (method.params || [])
    .map(p => p.optional ? `${p.name}?` : p.name)
    .join(', ');
  return `${receiver}:${method.name}(${params})`;
}

function classAnchor(cls) {
  return cls.name.toLowerCase();
}

function methodAnchor(cls, method) {
  return `${cls.name}-${method.name}`.toLowerCase();
}

// Shared body for both top-level functions and class methods. `subLevel`
// controls the heading depth of the Parameters/Returns/Errors sub-sections so
// they nest correctly under the member's own heading.
function MemberBody({ item, subLevel = 4 }) {
  const SubHeading = `h${subLevel}`;
  return (
    <>
      <DeprecatedBanner deprecated={item.deprecated} />
      <NoteBanner note={item.note} />

      {Array.isArray(item.description) ? (<Markdown>{item.description.join("\n")}</Markdown>) : (<Markdown>{item.description}</Markdown>)}

      {item.params?.length > 0 && (
        <>
          <SubHeading>Parameters</SubHeading>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {item.params.map(p => (
                <tr key={p.name}>
                  <td><code>{p.name}{p.optional ? '?' : ''}</code></td>
                  <td><code>{p.type}</code></td>
                  <td><Markdown>{p.description}</Markdown></td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {item.returns?.length > 0 && (
        <>
          <SubHeading>Returns</SubHeading>
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {item.returns.map((r, i) => (
                <tr key={i}>
                  <td><code>{r.type}{r.optional ? '?' : ''}</code></td>
                  <td><Markdown>{r.description}</Markdown></td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {item.errors?.length > 0 && (
        <>
          <SubHeading>Errors</SubHeading>
          <ul>
            {item.errors.map((e, i) => (
              <li key={i}><code>{e}</code></li>
            ))}
          </ul>
        </>
      )}
    </>
  );
}

function FunctionDoc({ func, namespace }) {
  return (
    <div className={styles.functionDoc}>
      <h3 id={func.name}>
        <code>{buildSignature(namespace, func)}</code>
      </h3>
      <MemberBody item={func} subLevel={4} />
    </div>
  );
}

function MethodDoc({ cls, method }) {
  const receiver = cls.receiver || cls.name.toLowerCase();
  return (
    <div className={styles.methodDoc}>
      <h4 id={methodAnchor(cls, method)}>
        <code>{buildMethodSignature(receiver, method)}</code>
      </h4>
      <MemberBody item={method} subLevel={5} />
    </div>
  );
}

function ClassDoc({ cls }) {
  return (
    <div className={styles.classDoc}>
      <h3 id={classAnchor(cls)}>
        <code>{cls.name}</code>
      </h3>

      {Array.isArray(cls.description) ? (<Markdown>{cls.description.join("\n")}</Markdown>) : (<Markdown>{cls.description}</Markdown>)}

      {cls.methods?.map(method => (
        <MethodDoc key={method.name} cls={cls} method={method} />
      ))}
    </div>
  );
}

function ClassesSection({ classes }) {
  if (!classes?.length) return null;
  return (
    <>
      <h2 id="classes">Classes</h2>
      {classes.map(cls => (
        <ClassDoc key={cls.name} cls={cls} />
      ))}
    </>
  );
}

function ConstantsSection({ constants }) {
  if (!constants?.length) return null;
  return (
    <>
      <h2 id="constants">Constants</h2>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {constants.map(c => (
            <tr key={c.name}>
              <td><code>{c.name}</code></td>
              <td><code>{c.type}</code></td>
              <td><Markdown>{c.description}</Markdown></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export default function NamespaceDocs({ data }) {
  return (
    <div>
      <Markdown className={styles.namespaceDescription}>{data.description}</Markdown>
      <ConstantsSection constants={data.constants} />
      {data.functions?.length > 0 && <h2 id="functions">Functions</h2>}
      {data.functions?.map(func => (
        <FunctionDoc key={func.name} func={func} namespace={data.namespace} />
      ))}
      <ClassesSection classes={data.classes} />
    </div>
  );
}
