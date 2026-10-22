import { createRoot } from 'react-dom/client';
import { BLESSING, VERSION } from '@nyaarink/version';
import './style.css';
console.log(BLESSING);
createRoot(document.getElementById('root')!).render(<main><h1>NyaaRink</h1><p>工程骨架 · {VERSION}</p><p>邀请服务尚未开放。</p><footer>{BLESSING}</footer></main>);
