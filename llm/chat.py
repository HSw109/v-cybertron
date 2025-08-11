from openai import OpenAI

client = OpenAI(
  base_url="https://api.featherless.ai/v1",
  api_key="rc_c0ab40439058c60e539eee6ef210353c2ae6d70da86558be2d306bcd13515cca",
)

response = client.chat.completions.create(
  model='trendmicro-ailab/Llama-Primus-Reasoning',
  messages=[
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello!"}
  ],
)
print(response.model_dump()['choices'][0]['message']['content'])
