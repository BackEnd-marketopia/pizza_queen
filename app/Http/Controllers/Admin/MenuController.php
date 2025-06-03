<?php

namespace App\Http\Controllers\Admin;

use App\CentralLogics\Helpers;
use App\Http\Controllers\Controller;
use App\Models\Menu;
use Illuminate\Http\Request;

class MenuController extends Controller
{
    public function index()
    {
        $menus = Menu::paginate(10);

        return view('admin-views.menu.index', compact('menus'));
    }

    public function create()
    {
        return view('admin-views.menu.create');
    }

    public function store(Request $request)
    {
        $request->validate([
            'image' => 'required|image|mimes:jpg,jpeg,png,gif|max:2048',
        ]);

        $imagePath = $request->file('image')->store('menus', 'public');
        Menu::create([
            'image' => $imagePath,
        ]);

        return redirect()->route('admin.menu.menu.index')->with('success', translate('Menu added successfully.'));
    }

    public function edit(string $id)
    {
        $menu = Menu::findOrFail($id);

        return view('admin-views.menu.edit', compact('menu'));
    }

    public function update(Request $request, string $id)
    {
        $menu = Menu::findOrFail($id);

        $request->validate([
            'image' => 'nullable|image|mimes:jpg,jpeg,png,gif|max:2048',
        ]);

        if ($request->hasFile('image')) {
            $imagePath = $request->file('image')->store('menus', 'public');
            $menu->update(['image' => $imagePath]);
        }

        return redirect()->route('admin.menu.menu.index')->with('success', translate('Menu updated successfully.'));
    }

    public function destroy(string $id)
    {
        $menu = Menu::findOrFail($id);

        $menu->delete();

        return redirect()->route('admin.menu.menu.index')->with('success', translate('Menu deleted successfully.'));
    }
}
