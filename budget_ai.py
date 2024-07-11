import openai
import os

def get_budget(transactions):
    openai.api_key = os.getenv('OPENAI_API_KEY')

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a budgeting assistant."},
            {"role": "user", "content": f"Here are my monthly transactions: {transactions}. Can you create a budget for me based on these transactions?"}
        ]
    )

    budget = response['choices'][0]['message']['content']
    print(budget)
    return budget

