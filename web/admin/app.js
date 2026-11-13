// Entry point: decides between the sign-in screen and the dashboard, draws
// the shell (sidebar, or top bar with a menu on a narrow screen) and maps
// the hash route to a page.

import { html, render, useEffect, useErrorBoundary, useRef, useState } from './vendor/htm-preact.js';
import { api, onForbidden, onUnauthorized } from './lib/api.js';
import { startLive, stopLive, useLiveState } from './lib/live.js';
import { Icon, Notice, ROLE_NAMES, Session, Toasts, can, useSession } from './lib/ui.js';
import { Account, SignIn } from './pages/account.js';
import { Admins } from './pages/admins.js';
import { Bans } from './pages/bans.js';
import { Connections } from './pages/connections.js';
import { Device, Devices } from './pages/devices.js';
import { Logs } from './pages/logs.js';
import { Overview } from './pages/overview.js';
import { Room } from './pages/room.js';
import { Rooms } from './pages/rooms.js';
import { Settings } from './pages/settings.js';

const NAV = [
  { path: '', label: 'Overview', icon: 'overview' },
  { path: 'rooms', label: 'Rooms', icon: 'rooms' },
  { path: 'connections', label: 'Connections', icon: 'connections' },
  { path: 'devices', label: 'Devices', icon: 'devices' },
  { path: 'bans', label: 'Bans', icon: 'bans' },
  { path: 'logs', label: 'Logs', icon: 'logs' },
  { path: 'settings', label: 'Settings', icon: 'settings' },
  { path: 'admins', label: 'Administrators', icon: 'admins', role: 'owner' },
];

// "#/rooms/12" -> ['rooms', '12']
const parseRoute = () => location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);

function useRoute() {
  const [route, setRoute] = useState(parseRoute);
  useEffect(() => {
    const onChange = () => setRoute(parseRoute());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
}

// The page for a route, or null when there is none.
function pageFor([section = '', item, rest], me) {
  if (rest !== undefined) return null;
  if (item !== undefined) {
    if (section === 'rooms' && /^\d+$/.test(item)) return html`<${Room} key=${item} id=${item} />`;
    if (section === 'devices') return html`<${Device} key=${item} identity=${item} />`;
    return null;
  }
  switch (section) {
    case '':
      return html`<${Overview} />`;
    case 'rooms':
      return html`<${Rooms} />`;
    case 'connections':
      return html`<${Connections} />`;
    case 'devices':
      return html`<${Devices} />`;
    case 'bans':
      return html`<${Bans} />`;
    case 'logs':
      return html`<${Logs} />`;
    case 'settings':
      return html`<${Settings} />`;
    case 'admins':
      return can(me, 'owner')
        ? html`<${Admins} />`
        : html`<${Notice} kind="warn">Only owners can manage administrator accounts.<//>`;
    case 'account':
      return html`<${Account} />`;
    default:
      return null;
  }
}

// A page that throws is replaced by a message; the shell stays usable.
function Boundary({ children }) {
  const [error] = useErrorBoundary((err) => console.error(err));
  if (!error) return children;
  return html`
    <${Notice} kind="error">
      <p>This page ran into a problem and could not be shown.</p>
      <button type="button" class="btn small" onClick=${() => location.reload()}>Reload the dashboard</button>
    <//>
  `;
}

function Shell() {
  const { me, settings } = useSession();
  const route = useRoute();
  const path = route.join('/');
  const [menu, setMenu] = useState(false);
  const main = useRef(null);
  const visited = useRef(false);
  const stream = useLiveState();

  const section = route[0] || '';
  const current = NAV.find((n) => n.path === section);
  const name = (settings && settings.server_name) || 'Lanora';

  useEffect(() => {
    document.title = `${current ? current.label : section === 'account' ? 'Account' : 'Not found'} · ${name}`;
  }, [section, name]);

  // A new page starts at its top, with the keyboard focus on its content
  // rather than left behind on the link that was followed.
  useEffect(() => {
    setMenu(false);
    if (visited.current) {
      window.scrollTo(0, 0);
      main.current.focus({ preventScroll: true });
    }
    visited.current = true;
  }, [path]);

  const page = pageFor(route, me);
  return html`
    <div class="shell">
      <button type="button" class="btn skip" onClick=${() => main.current.focus()}>Skip to content</button>
      <header class=${menu ? 'side open' : 'side'} onKeyDown=${(e) => e.key === 'Escape' && setMenu(false)}>
        <div class="side-top">
          <a class="brand" href="#/">
            <img src="/logo.svg" width="28" height="28" alt="" />
            <span>${name}</span>
          </a>
          <button
            type="button"
            class="btn quiet icon-only menu-toggle"
            aria-label="Menu"
            aria-expanded=${menu ? 'true' : 'false'}
            aria-controls="nav"
            onClick=${() => setMenu(!menu)}
          >
            <${Icon} name=${menu ? 'close' : 'menu'} size=${20} />
          </button>
        </div>
        <nav id="nav" class="nav" aria-label="Main">
          <ul>
            ${NAV.filter((n) => !n.role || can(me, n.role)).map(
              (n) => html`
                <li key=${n.path}>
                  <a
                    href=${`#/${n.path}`}
                    class=${n.path === section ? 'active' : ''}
                    aria-current=${n.path === section ? 'page' : undefined}
                  >
                    <${Icon} name=${n.icon} />${n.label}
                  </a>
                </li>
              `,
            )}
          </ul>
          <div class="nav-foot">
            <a
              href="#/account"
              class=${section === 'account' ? 'active' : ''}
              aria-current=${section === 'account' ? 'page' : undefined}
            >
              <${Icon} name="account" />
              <span class="who"><span>${me.username}</span><small>${ROLE_NAMES[me.role]}</small></span>
            </a>
          </div>
        </nav>
      </header>
      <main id="main" class="main" tabindex="-1" ref=${main}>
        ${stream === 'down' &&
        html`<${Notice} kind="warn" class="banner">The live connection to the server was lost. Reconnecting…<//>`}
        <${Boundary} key=${path}>
          ${page ||
          html`
            <${Notice}>
              <p>There is no page at this address.</p>
              <a class="btn small" href="#/">Go to the overview</a>
            <//>
          `}
        <//>
      </main>
      <${Toasts} />
    </div>
  `;
}

function App() {
  // undefined while the session is being checked, null when signed out.
  const [me, setMe] = useState(undefined);
  const [settings, setSettings] = useState(null);
  const [notice, setNotice] = useState('');
  const [failure, setFailure] = useState(null);

  const check = () => {
    setFailure(null);
    api
      .get('/me')
      .then(({ admin }) => setMe(admin))
      .catch((err) => err.status === 401 || setFailure(err));
  };

  useEffect(() => {
    // Any request can find the session gone; say why the sign-in screen is
    // back, unless nobody was signed in to begin with.
    onUnauthorized((err) => {
      setMe((was) => {
        if (was) setNotice(err.message);
        return null;
      });
    });
    // The account's role changed under us: fetch it again so that controls
    // it may no longer use disappear.
    onForbidden(() => {
      api
        .get('/me')
        .then(({ admin }) => setMe(admin))
        .catch(() => {});
    });
    check();
  }, []);

  const signedIn = Boolean(me);
  useEffect(() => {
    if (!signedIn) return undefined;
    startLive();
    // The server's name heads the sidebar; the default capacity is offered
    // when creating a room.
    api
      .get('/settings')
      .then((r) => setSettings(r.settings))
      .catch(() => {});
    return () => {
      stopLive();
      setSettings(null);
    };
  }, [signedIn]);

  const signOut = async () => {
    try {
      await api.post('/logout');
    } catch {
      /* the cookie may already be gone; either way we are signed out here */
    }
    setNotice('');
    setMe(null);
  };

  if (failure) {
    return html`
      <main class="auth">
        <div class="card auth-card">
          <${Notice} kind="error">
            <p>${failure.message}</p>
            <button type="button" class="btn small" onClick=${check}>Try again</button>
          <//>
        </div>
      </main>
    `;
  }
  if (me === undefined) return html`<p class="boot loading">Loading…</p>`;
  if (me === null) {
    return html`<${SignIn}
      notice=${notice}
      onSignedIn=${(admin) => {
        setNotice('');
        setMe(admin);
      }}
    />`;
  }
  return html`<${Session.Provider} value=${{ me, settings, setSettings, signOut }}><${Shell} /><//>`;
}

// A path such as /rooms/12 (a link from somewhere, or a habit) is the same
// page under hash routing.
if (!['/', '/index.html'].includes(location.pathname)) location.replace(`/#${location.pathname}`);

const root = document.getElementById('app');
root.textContent = '';
render(html`<${App} />`, root);
