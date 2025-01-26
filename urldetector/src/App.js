import logo from './logo.svg';
import './App.css';

function App() {
  return (
    <div className="App">
      <header>
        <h1 className="Title">Malicious URL Detector</h1>
      </header>
      <main>
        <h2>
          This site analyzes URLs with an ML model trained on a dataset of malicious URLs
          to determine whether it is safe to click or enter the site.
        </h2>
        <form>
          <input type="text" id="url" name="url" placeholder="Enter URL here..." />
        </form>
        <form>
          <button className="button"> Start url analysis</button>
        </form>
        
      </main>
    </div>
  );
}

export default App;
