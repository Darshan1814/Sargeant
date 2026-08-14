import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Overview from './pages/Overview'
import CreateParser from './pages/CreateParser'
import CompareView from './pages/CompareView'
import LogBrowser from './pages/LogBrowser'
import ParserLibrary from './pages/ParserLibrary'
import OpsView from './pages/OpsView'
import Fetch from './pages/Fetch'
import Health from './pages/Health'
import Upload from './pages/Upload'

const NAV = [
  { to: '/',          label: 'Overview' },
  { to: '/fetch',     label: 'Fetch' },
  { to: '/upload',    label: 'Upload' },
  { to: '/logs',      label: 'Log Browser' },
  { to: '/parsers',   label: 'Parsers' },
  { to: '/parsers/new', label: 'New Parser' },
  { to: '/compare',   label: 'Compare' },
  { to: '/health',    label: 'Health' },
  { to: '/ops',       label: 'Ops' },
]

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col">
        <nav className="bg-gray-900 border-b border-gray-700 px-6 py-3 flex items-center gap-6">
          <span className="text-cyan-400 font-bold text-lg tracking-wide">ULPF</span>
          {NAV.map(n => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) =>
                `text-sm px-3 py-1 rounded transition-colors ${
                  isActive
                    ? 'bg-cyan-700 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-gray-700'
                }`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <main className="flex-1 p-6">
          <Routes>
            <Route path="/"            element={<Overview />} />
            <Route path="/fetch"       element={<Fetch />} />
            <Route path="/upload"      element={<Upload />} />
            <Route path="/logs"        element={<LogBrowser />} />
            <Route path="/parsers"     element={<ParserLibrary />} />
            <Route path="/parsers/new" element={<CreateParser />} />
            <Route path="/compare"     element={<CompareView />} />
            <Route path="/health"      element={<Health />} />
            <Route path="/ops"         element={<OpsView />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
