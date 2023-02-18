using Android.App;
using Android.OS;
using Android.Runtime;
using Android.Text;
using Android.Views;
using Android.Views.InputMethods;
using Android.Widget;
using AndroidX.AppCompat.App;
using AndroidX.Core.Text;
using Cats.CertificateTransparency;
using Cats.CertificateTransparency.Models;
using Google.Android.Material.FloatingActionButton;
using Google.Android.Material.Snackbar;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using DotNetX509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace Samples.Droid
{
    [Activity(
        Label = "@string/app_name",
        Theme = "@style/AppTheme.NoActionBar",
        WindowSoftInputMode = SoftInput.AdjustResize,
        MainLauncher = true)]
    public class MainActivity : AppCompatActivity
    {
        private readonly Dictionary<string, string> _hostnameHtmlResults = new Dictionary<string, string>();

        private HttpClient _httpClient;

        private bool _isLoading = false;

        private EditText _uriEditText;
        private TextView _resultText;

        protected override void OnCreate(Bundle savedInstanceState)
        {
            _ = Instance.LogListService.LoadLogListAsync(default);

            base.OnCreate(savedInstanceState);
            SetContentView(Resource.Layout.activity_main);

            var toolbar = FindViewById<AndroidX.AppCompat.Widget.Toolbar>(Resource.Id.toolbar);
            SetSupportActionBar(toolbar);

            _uriEditText = FindViewById<EditText>(Resource.Id.edit_url);
            _resultText = FindViewById<TextView>(Resource.Id.result_txt);

            var fab = FindViewById<FloatingActionButton>(Resource.Id.fab);
            fab.Click += FabOnClick;

            _uriEditText.SetOnKeyListener(new EnterKeyListener(() => fab.CallOnClick()));

            var handler = new CatsAndroidMessageHandler(VerifyCtResult);
            _httpClient = new HttpClient(handler);
        }

        public override bool OnCreateOptionsMenu(IMenu menu)
        {
            MenuInflater.Inflate(Resource.Menu.menu_main, menu);
            return true;
        }

        public override bool OnOptionsItemSelected(IMenuItem item)
        {
            int id = item.ItemId;
            if (id == Resource.Id.action_settings)
            {
                return true;
            }

            return base.OnOptionsItemSelected(item);
        }

        private async void FabOnClick(object sender, EventArgs eventArgs)
        {
            if (_isLoading || string.IsNullOrWhiteSpace(_uriEditText.Text) || sender is not View)
                return;

            _isLoading = true;

            var view = (View)sender;
            var hostname = string.Empty;
            var exceptionHtml = string.Empty;

            try
            {
                var imm = GetSystemService(InputMethodService) as InputMethodManager;
                imm.HideSoftInputFromWindow(view.WindowToken, HideSoftInputFlags.None);
                _uriEditText.ClearFocus();

                var uri = new Uri(_uriEditText.Text);
                hostname = uri.Host;

                _resultText.Text = $"Loading '{_uriEditText.Text}'...";

                await _httpClient.GetAsync(uri);
            }
            catch (Exception ex)
            {
                Snackbar.Make(view, ex.Message, Snackbar.LengthShort).Show();
                exceptionHtml = $"<p><b># Exception #</b><p>{ex}</p>";
            }
            finally
            {
                _isLoading = false;
            }

            var htmlResult = _hostnameHtmlResults.ContainsKey(hostname)
                ? $"{_hostnameHtmlResults[hostname]}{exceptionHtml}"
                : $"<p>Loaded '{_uriEditText.Text}', no SCT information!<p>{exceptionHtml}";

            _resultText.TextFormatted = HtmlCompat.FromHtml(htmlResult, HtmlCompat.FromHtmlModeLegacy);
        }

        private bool VerifyCtResult(string hostname, IList<DotNetX509Certificate> certChain, CtVerificationResult ctVerificationResult)
        {
            var leafCert = certChain.First();

            var builder = new StringBuilder();

            builder.AppendFormat("<p><b># Hostname:</b> {0}</p>", hostname);
            builder.AppendFormat("<p><b># Result:</b> {0}</p>", ctVerificationResult.Description);
            builder.Append("<p><b># Leaf #</b></p>");
            builder.AppendFormat("<p>{0}</p>", leafCert.ToString().Replace(System.Environment.NewLine, "<br />"));
            builder.AppendLine("<p><b># Chain #</b></p>");

            for (var i = 0; i < certChain.Count; i++)
            {
                builder.AppendFormat("<p><b>## [{0}] ##</b></p>", i);
                builder.AppendFormat("<p>{0}</p>", certChain[i].ToString().Replace(System.Environment.NewLine, "<br />"));
            }

            _hostnameHtmlResults[hostname] = builder.ToString();

            return ctVerificationResult.IsValid;
        }

        private class EnterKeyListener : Java.Lang.Object, View.IOnKeyListener
        {
            private readonly Action _action;

            public EnterKeyListener(Action onEnterKeyPress)
            {
                _action = onEnterKeyPress;
            }

            public bool OnKey(View v, [GeneratedEnum] Keycode keyCode, KeyEvent e)
            {
                if (keyCode == Keycode.Enter)
                {
                    _action?.Invoke();
                    return true;
                }

                return false;
            }
        }
    }
}
