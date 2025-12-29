using Android.App;
using Android.OS;
using Android.Views;
using AndroidX.Core.View;
using System.Reflection;
using Xamarin.Android.NUnitLite;

namespace Tests.Droid
{
    [Activity(Label = "@string/app_name", MainLauncher = true)]
    public class MainActivity : TestSuiteActivity, IOnApplyWindowInsetsListener
    {
        protected override void OnCreate(Bundle savedInstanceState)
        {
            var content = FindViewById(Android.Resource.Id.Content);
            ViewCompat.SetOnApplyWindowInsetsListener(content, this);

            // tests can be inside the main assembly
            this.AddTest(Assembly.GetExecutingAssembly());
            // or in any reference assemblies
            // AddTest (typeof (Your.Library.TestClass).Assembly);

            // Once you called base.OnCreate(), you cannot add more assemblies.
            base.OnCreate(savedInstanceState);
        }

        #region IOnApplyWindowInsetsListener
        public WindowInsetsCompat OnApplyWindowInsets(View v, WindowInsetsCompat insets)
        {
            var systemBars = insets.GetInsets(WindowInsetsCompat.Type.SystemBars());

            v.SetPadding(
                systemBars.Left,
                systemBars.Top,
                systemBars.Right,
                systemBars.Bottom
            );

            return WindowInsetsCompat.Consumed;
        }
        #endregion
    }
}