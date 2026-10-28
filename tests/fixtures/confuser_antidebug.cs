using System;
using System.Reflection;
using System.Threading;

// Token: 0x02000001 RID: 1
internal partial class <Module>
{
	// Token: 0x06000002 RID: 2 RVA: 0x00002064 File Offset: 0x00000264
	private static void ‮‮⁭⁮‍​‬​‌‍‪‌‭⁬‭‮‏‭⁪⁯‌‪‭‍⁮​⁯⁭‪⁪‪⁯⁭‍‏⁮‫‬⁯‫‮()
	{
		string str = "COR";
		for (;;)
		{
			IL_06:
			uint num = 3442226333U;
			for (;;)
			{
				uint num2;
				switch ((num2 = (num ^ 2399871976U)) % 9U)
				{
				case 0U:
				{
					MethodInfo method;
					num = (((method != null) ? 4143260718U : 2255836361U) ^ num2 * 1449767180U);
					continue;
				}
				case 1U:
				{
					Thread thread;
					thread.IsBackground = true;
					thread.Start(null);
					num = (num2 * 580075008U ^ 2567525357U);
					continue;
				}
				case 2U:
				{
					Type typeFromHandle;
					MethodInfo method = typeFromHandle.GetMethod("GetEnvironmentVariable", new Type[]
					{
						typeof(string)
					});
					num = (num2 * 675101377U ^ 2675475123U);
					continue;
				}
				case 3U:
				{
					MethodInfo method;
					num = (((!"1".Equals(method.Invoke(null, new object[]
					{
						str + "_ENABLE_PROFILING"
					}))) ? 3378893701U : 2293477814U) ^ num2 * 1490916778U);
					continue;
				}
				case 4U:
				{
					Thread thread = new Thread(new ParameterizedThreadStart(<Module>.⁭‍​‮‍⁫‏‬⁯⁪‫‬⁬⁮‫⁯‬⁬​⁪⁫⁭⁫⁬‪‍‪‫⁪‮⁪​‬‎⁮‎‫‬​‪‮));
					num = 3198791400U;
					continue;
				}
				case 5U:
					goto IL_06;
				case 6U:
					Environment.FailFast(null);
					num = (num2 * 788866795U ^ 1972299535U);
					continue;
				case 8U:
				{
					Type typeFromHandle = typeof(Environment);
					num = (num2 * 884458529U ^ 1161631898U);
					continue;
				}
				}
				return;
			}
		}
	}
}
