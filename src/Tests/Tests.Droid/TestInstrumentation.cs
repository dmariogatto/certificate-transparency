using Android.App;
using Android.Runtime;
using System;
using System.Reflection;
using Xamarin.Android.NUnitLite;

namespace Tests.Droid
{
    // adb shell am instrument -w com.tests.certificatetransparency/app.tests.TestInstrumentation

    [Instrumentation(Name = "app.tests.TestInstrumentation")]
    public class TestInstrumentation : TestSuiteInstrumentation
    {
        public TestInstrumentation(IntPtr handle, JniHandleOwnership transfer) : base(handle, transfer)
        {
        }

        protected override void AddTests()
        {
            AddTest(Assembly.GetExecutingAssembly());
        }
    }
}