import { useMemo, useState } from 'react';
import { Activity, ArrowRight, CheckCircle2, Disc3, HardDrive, History, Layers3, Monitor, Settings2, ShieldCheck, Sparkles, Usb, X } from 'lucide-react';

type PickedImage = { name: string; size: number };
const extensions = ['iso','img','dmg','raw','bin','vhd','vhdx','wim','esd'];
const sizeLabel = (n:number) => n >= 1024 ** 3 ? (n / 1024 ** 3).toFixed(2) + ' GB' : (n / 1024 ** 2).toFixed(1) + ' MB';

export default function App() {
  const [file,setFile] = useState<PickedImage|null>(null);
  const [tab,setTab] = useState('Create media');
  const [drag,setDrag] = useState(false);
  const [notice,setNotice] = useState('');
  const [confirm,setConfirm] = useState(false);
  const accepted = useMemo(() => !!file && extensions.some(ext => file.name.toLowerCase().endsWith('.'+ext)),[file]);
  function choose(f?:File) {
    if (!f) return;
    if (!extensions.some(ext => f.name.toLowerCase().endsWith('.'+ext))) { setNotice('This file extension is not in the current candidate list.'); return; }
    setFile({name:f.name,size:f.size}); setNotice('Image selected. Compatibility inspection requires the desktop engine.');
  }
  const nav = [{label:'Create media',icon:Disc3},{label:'My drives',icon:HardDrive},{label:'Creation history',icon:History},{label:'AI assistant',icon:Sparkles}];
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-icon"><Layers3/></div><div><b>ALLBOOT</b><small>ISO MAKER</small></div></div>
      <div className="nav-caption">WORKSPACE</div>
      {nav.map(({label,icon:Icon})=><button key={label} className={'nav-link '+(tab===label?'selected':'')} onClick={()=>setTab(label)}><Icon size={17}/>{label}</button>)}
      <div className="sidebar-bottom"><div className="engine-status"><span className="status-light"/><div><b>Native engine</b><small>Not connected in web preview</small></div></div><button className="nav-link" onClick={()=>setTab('Settings')}><Settings2 size={17}/>Settings</button><small className="version">ALLBOOT · PREVIEW 0.1.0</small></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="crumb">Workspace <span>/</span> <b>{tab}</b></div><div className="top-right"><span><ShieldCheck size={15}/> Local-first workflow</span><div className="avatar">AB</div></div></header>
      {tab==='Create media' ? <>
        <section className="hero"><div className="eyebrow"><i/> UNIVERSAL BOOT MEDIA WORKSPACE</div><h1>Make any drive<br/><em>boot-ready.</em></h1><p>Prepare bootable USB drives, HDDs and SSDs from operating-system images with one guided workflow.</p><div className="platform-chips"><span><Monitor size={14}/> Windows</span><span>◈ Linux</span><span>◉ macOS</span><span>＋ Other compatible images</span></div></section>
        <section className="work-grid">
          <article className="panel"><div className="panel-heading"><div><small>01 · SOURCE IMAGE</small><h2>Choose your image</h2></div><label>REQUIRED</label></div>
            <label className={'drop-area '+(drag?'dragging':'')} onDragOver={e=>{e.preventDefault();setDrag(true)}} onDragLeave={()=>setDrag(false)} onDrop={e=>{e.preventDefault();setDrag(false);choose(e.dataTransfer.files[0]);}}>
              <input type="file" accept={extensions.map(x=>'.'+x).join(',')} onChange={e=>choose(e.target.files?.[0])}/>
              <div className="upload-glyph">↑</div><b>{file?.name || 'Drop your image file here'}</b><span>{file ? sizeLabel(file.size) : 'or click to browse your computer'}</span><small>ISO · IMG · DMG · RAW · BIN · VHD · WIM · ESD</small>
            </label>
            {file && <div className="picked-file"><Disc3 size={17}/><div><b>{file.name}</b><small>{sizeLabel(file.size)}</small></div><button onClick={()=>setFile(null)} aria-label="Remove image"><X size={16}/></button></div>}
            <div className="hint"><Sparkles size={15}/> Image structure and boot compatibility will be inspected before writing.</div>
          </article>
          <article className="panel"><div className="panel-heading"><div><small>02 · DESTINATION</small><h2>Select a drive</h2></div><label>REQUIRED</label></div>
            <div className="drive-placeholder"><div className="drive-icon"><Usb size={28}/></div><b>Waiting for a connected drive</b><p>USB, HDD and SSD detection is provided by the native desktop engine—not this browser preview.</p><small><Activity size={13}/> DEVICE SCAN NOT AVAILABLE IN WEB PREVIEW</small></div>
            <div className="field-label">DESTINATION DRIVE</div><select disabled><option>Connect a drive in the desktop app</option></select>
            <div className="warning"><ShieldCheck size={16}/> Writing can erase all data on the selected destination. Exact device identity must be confirmed.</div>
          </article>
        </section>
        <section className="bottom-bar"><div className="safety"><CheckCircle2 size={19}/><div><b>Safety-first workflow</b><small>Image validation · Device identity · Write verification</small></div></div><button className="primary" disabled={!accepted} onClick={()=>setConfirm(true)}>Review preparation <ArrowRight size={17}/></button></section>
        {notice && <p className="notice">{notice}</p>}
      </> : <section className="placeholder"><div className="placeholder-icon"><Sparkles/></div><h2>{tab}</h2><p>This workspace will be available when the native desktop engine and supporting services are implemented.</p><button className="secondary" onClick={()=>setTab('Create media')}>Back to create media</button></section>}
      <footer><span>ALLBOOT ISO MAKER</span><span>UNIVERSAL BOOT MEDIA <i>·</i> DESKTOP PREVIEW</span></footer>
    </main>
    {confirm && <div className="modal-backdrop" role="presentation"><div className="modal" role="dialog" aria-modal="true"><div className="modal-symbol"><ShieldCheck/></div><h2>Desktop engine required</h2><p><b>{file?.name}</b> is selected. This preview cannot enumerate physical drives, partition disks or write images. No drive has been modified.</p><button className="primary modal-button" onClick={()=>setConfirm(false)}>Got it</button></div></div>}
  </div>;
}