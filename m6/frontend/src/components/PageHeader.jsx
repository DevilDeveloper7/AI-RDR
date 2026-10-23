import Icon from './Icon.jsx'
import SearchBox from './SearchBox.jsx'

// Every page starts with this header: optional back link, title and subtitle on the left, page actions and search on the right.
export default function PageHeader({ title, sub, back, children }) {
  return (
    <>
      {back && <div className="backrow"><button className="back" onClick={back.onClick}><Icon name="back" />{back.label}</button></div>}
      <div className="ph">
        <div className="ttl"><h2>{title}</h2>{sub && <p>{sub}</p>}</div>
        <div className="sp">{children}<SearchBox /></div>
      </div>
    </>
  )
}
